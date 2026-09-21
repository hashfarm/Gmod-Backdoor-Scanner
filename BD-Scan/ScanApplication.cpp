#include "ScanApplication.h"
#include "HtmlReport.h"
#include "SarifReport.h"
#include "ScanTasks.h"
#include "MemoryBudget.h"
#include "MemoryStream.h"
#include "CompositeScope.h"
#include "Heuristics.h"
#include "ScanCache.h"
#include "BinaryStrings.h"
#include "Console.h"
#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <thread>
#include <algorithm>
#include <mutex>
#include <atomic>
#include <set>
#include <map>
#include <cctype>
#include <cstdlib>
#include <ctime>
#include <cwctype>
#include <nlohmann/json.hpp>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

#include "Rules.h"
#include "Scanner.h"
#include "Lzma.h"
#include "Report.h"
#include "Composite.h"
#include "CleanString.h"
#include "GMAReader.h"
#include "SHA256.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

static constexpr int64_t kMaxScanBytes = 64ll * 1024 * 1024;
static constexpr int64_t kMaxArchiveBytes = 512ll * 1024 * 1024;
static constexpr uint64_t kDecompressGuessRatio = 64;
static constexpr uint64_t kDecompressGuessFloor = 4ull * 1024 * 1024;
static constexpr uint64_t kDecompressGuessGrowth = 8;
static constexpr int kMaxArchiveDepth = 4;
static constexpr size_t kMaxConsoleFindings = 40;
static constexpr size_t kMinConsoleFindings = 1;
static constexpr int kConsoleSeverityFloor = 1;
static constexpr size_t kTopFilesInSummary = 5;

enum ExitCode {
    kExitClean = 0,
    kExitDetections = 1,
    kExitError = 2,
    kExitIncomplete = 3
};

static constexpr size_t kSkipSamplesInSummary = 5;

std::string EnvironmentValue(const char* name) {
#ifdef _WIN32
    char buffer[32] = {};
    size_t length = 0;
    if (getenv_s(&length, buffer, sizeof(buffer), name) != 0 || length == 0) return std::string();
    return std::string(buffer);
#else
    const char* value = std::getenv(name);
    return value != nullptr ? std::string(value) : std::string();
#endif
}

std::mutex g_reportedMutex;
std::atomic<int> g_filesProcessed{0};
std::atomic<int> g_detections{0};
std::set<std::string> g_knownBadMatched;
std::atomic<int> g_decompressedArchives{0};
std::atomic<int> g_compositeHits{0};
std::atomic<int> g_whitelistedFiles{0};

std::string g_minSeverity = "low";
std::set<std::string> g_excludedTags;
std::string g_rulesetVersion;
std::string g_policyVersion;
bool g_quietMode = false;
bool g_generateHtml = false;
bool g_generateSarif = false;
bool g_diffMode = false;
bool g_interactive = false;
fs::path g_outputDir = ".";
fs::path g_ruleDir;

std::set<std::string> g_knownBadHashes;
std::vector<Detection> g_reported;

PatternSet g_patterns;
Whitelist g_whitelist;
ReportFilter g_filter;
CompositeRuleSet g_composites;
std::mutex g_scanCountsMutex;
std::map<std::string, CompositeEvidence> g_scopeEvidence;
fs::path g_scanRoot;
std::unique_ptr<MemoryBudget> g_archiveMemory;
std::unique_ptr<ScanCache> g_cache;
SkipRegistry g_skipped;

std::string PathToUtf8(const fs::path& path) {
    const auto encoded = path.u8string();
    return std::string(encoded.begin(), encoded.end());
}

fs::path OutputPath(const char* name) {
    return g_outputDir / name;
}

std::set<std::string> LoadBaselineKeys(const fs::path& path) {
    std::set<std::string> keys;
    std::ifstream file(path);
    if (!file.is_open()) return keys;

    try {
        json lastScan;
        file >> lastScan;
        if (lastScan.value("schema_version", 0) != 2 || !lastScan.value("complete", false) ||
            lastScan.value("min_severity", "") != "low" || lastScan.value("diff_mode", true) ||
            (lastScan.contains("excluded_tags") && !lastScan["excluded_tags"].empty()) ||
            lastScan.value("ruleset_version", "") != g_rulesetVersion ||
            lastScan.value("policy_version", "") != g_policyVersion ||
            lastScan.value("scan_root", "") != NormalizedPath(g_scanRoot)) {
            std::cerr << "Warning: Baseline is incomplete, outdated or uses different rules/settings; reporting all findings." << std::endl;
            return {};
        }

        if (lastScan.contains("detections") && lastScan["detections"].is_array()) {
            for (const auto& det : lastScan["detections"]) {
                Detection detection;
                detection.file = det.value("file", "");
                detection.lineNumber = det.value("line_number", 0);
                detection.detection = det.value("detection", "");
                detection.id = det.value("id", "");
                detection.fingerprint = det.at("fingerprint").get<std::string>();
                if (detection.fingerprint.size() != 64) throw std::runtime_error("invalid baseline fingerprint");
                keys.insert(ReportFilter::Key(detection));
            }
        }
    }
    catch (const std::exception&) {
        keys.clear();
        std::cerr << "Warning: Could not parse " << PathToUtf8(path) << ", diff mode will report everything." << std::endl;
    }
    return keys;
}

json DetectionToJson(const Detection& detection) {
    json item;
    item["id"] = detection.id;
    item["detection"] = detection.detection;
    item["severity"] = detection.severity;
    item["hint"] = detection.hint;
    item["line_number"] = detection.lineNumber;
    item["line_text"] = detection.lineText;
    if (!detection.decodedContent.empty()) item["decoded"] = detection.decodedContent;
    if (!detection.context.empty()) {
        item["context_start"] = detection.contextStart;
        item["context"] = detection.context;
    }
    return item;
}

Detection DetectionFromJson(const json& item, const std::string& file, const std::string& hash) {
    Detection detection;
    detection.file = file;
    detection.id = item.at("id").get<std::string>();
    detection.detection = item.at("detection").get<std::string>();
    detection.severity = item.at("severity").get<std::string>();
    if (!IsValidSeverity(detection.severity)) throw std::runtime_error("bad severity in cache");
    detection.hint = item.value("hint", "");
    detection.lineNumber = item.value("line_number", 0);
    detection.lineText = item.value("line_text", "");
    detection.decodedContent = item.value("decoded", "");
    detection.contextStart = item.value("context_start", 0);
    if (item.contains("context")) {
        detection.context = item.at("context").get<std::vector<std::string>>();
    }
    detection.hash = hash;
    detection.fingerprint = hash;
    return detection;
}

void LoadScanCache(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) return;

    std::map<std::string, ScanCacheEntry> loaded;
    try {
        json document;
        input >> document;
        const std::set<std::string> cachedTags =
            document.value("excluded_tags", std::set<std::string>());
        if (document.value("schema_version", 0) != 1 ||
            document.value("scanner_version", "") != std::string(kScannerVersion) ||
            document.value("ruleset_version", "") != g_rulesetVersion ||
            document.value("policy_version", "") != g_policyVersion ||
            cachedTags != g_excludedTags) {
            if (!g_quietMode) {
                std::cout << "  " << con::Dim("Cache is from a different scanner or rule set; scanning everything.") << std::endl;
            }
            return;
        }
        for (const auto& item : document.at("files").items()) {
            ScanCacheEntry entry;
            entry.size = item.value().at("size").get<uint64_t>();
            entry.modified = item.value().at("modified").get<int64_t>();
            entry.hash = item.value().at("hash").get<std::string>();
            if (entry.hash.size() != 64) throw std::runtime_error("bad hash in cache");
            for (const auto& detection : item.value().at("detections")) {
                entry.detections.push_back(DetectionFromJson(detection, item.key(), entry.hash));
            }
            loaded[item.key()] = std::move(entry);
        }
    }
    catch (const std::exception&) {
        std::cerr << "Warning: Could not read the cache at " << PathToUtf8(path)
                  << "; scanning everything." << std::endl;
        return;
    }
    g_cache->Adopt(std::move(loaded));
}

bool WriteTextFile(const fs::path& path, const std::string& content) {
    fs::path temporary = path;
    temporary += ".tmp." + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    std::error_code ec;
    try {
        std::ofstream out(temporary, std::ios::binary);
        if (!out.is_open()) return false;
        out << content;
        out.close();
        if (!out) { fs::remove(temporary, ec); return false; }
#ifdef _WIN32
        if (MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return true;
#else
        fs::rename(temporary, path, ec);
        if (!ec) return true;
#endif
    }
    catch (const std::exception&) {
        fs::remove(temporary, ec);
        throw;
    }
    fs::remove(temporary, ec);
    return false;
}

bool WriteJsonFile(const fs::path& path, const json& content) {
    return WriteTextFile(path, content.dump(4) + "\n");
}

bool SaveScanCache(const fs::path& path) {
    json files = json::object();
    for (const auto& entry : g_cache->Fresh()) {
        json item;
        item["size"] = entry.second.size;
        item["modified"] = entry.second.modified;
        item["hash"] = entry.second.hash;
        json detections = json::array();
        for (const Detection& detection : entry.second.detections) {
            detections.push_back(DetectionToJson(detection));
        }
        item["detections"] = detections;
        files[entry.first] = item;
    }

    json document;
    document["schema_version"] = 1;
    document["scanner_version"] = kScannerVersion;
    document["ruleset_version"] = g_rulesetVersion;
    document["policy_version"] = g_policyVersion;
    document["excluded_tags"] = g_excludedTags;
    document["files"] = files;
    return WriteJsonFile(path, document);
}

bool ReportDetection(const Detection& detection) {
    if (g_filter.Evaluate(detection) != Verdict::Report) return false;

    {
        std::lock_guard<std::mutex> lock(g_reportedMutex);
        g_reported.push_back(detection);
    }
    g_detections++;
    return true;
}

void NoteScanDetection(const Detection& detection, const std::string& scope) {
    if (detection.id.empty()) return;
    std::lock_guard<std::mutex> lock(g_scanCountsMutex);
    auto& files = g_scopeEvidence[scope][detection.id];
    if (files.count(detection.file) == 0) {
        files[detection.file] = { detection.id, detection.file, detection.lineNumber, detection.fingerprint };
    }
}

bool CheckKnownBadHash(const std::string& filePath, const std::string& hash, const std::string& scope,
                       const std::string& container = "") {
    if (g_knownBadHashes.find(hash) == g_knownBadHashes.end()) return false;

    Detection detection;
    detection.file = filePath;
    detection.container = container;
    detection.detection = "[CRITICAL] HASH-001 Known Backdoor (Hash Match)";
    detection.severity = "critical";
    detection.id = "HASH-001";
    detection.lineNumber = 0;
    detection.lineText = "File hash: " + hash;
    detection.hash = hash;
    detection.fingerprint = hash;

    NoteScanDetection(detection, scope);
    if (ReportDetection(detection)) {
        std::lock_guard<std::mutex> guard(g_reportedMutex);
        g_knownBadMatched.insert(hash);
    }
    return true;
}

bool IsBinaryModule(const fs::path& path) {
    const std::string normalized = NormalizedPath(path);
    return GMAReader::IsBinaryModuleName(normalized) || GMAReader::IsNativeBinaryName(normalized);
}

void ReportBinaryModule(const std::string& filePath, const std::string& hash,
                        const std::string& scope, const std::string& container) {
    Detection detection;
    detection.file = filePath;
    detection.container = container;
    detection.detection = "[HIGH] MOD-001 Binary Lua Module (native code, cannot be scanned)";
    detection.severity = "high";
    detection.id = "MOD-001";
    detection.lineNumber = 0;
    detection.lineText = "File hash: " + hash;
    detection.hash = hash;
    detection.fingerprint = hash;

    NoteScanDetection(detection, scope);
    if (ReportDetection(detection)) {

    }
}

std::string HashFile(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return "";

    SHA256 context;
    std::vector<char> buffer(64 * 1024);
    while (file) {
        file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = file.gcount();
        if (got <= 0) break;
        context.Update(reinterpret_cast<const uint8_t*>(buffer.data()), static_cast<size_t>(got));
    }
    if (file.bad()) return "";
    return context.Finalize();
}

void PublishFileDetections(const std::vector<Detection>& raw, const std::string& filePath,
                           const std::string& scope);

void ScanModuleStrings(const std::string& content, const std::string& filePath,
                       const std::string& scope, const std::string& container,
                       const std::string& hash) {
    bool truncated = false;
    const std::string strings = binstr::ExtractPrintableRuns(
        content, binstr::kMinimumRun, binstr::kMaximumOutput, &truncated);
    if (truncated) {
        g_skipped.Add(SkipReason::StringLimit, filePath,
                      "only the first " + std::to_string(binstr::kMaximumOutput / (1024 * 1024)) +
                      " MB of readable text was examined");
    }
    if (strings.empty()) return;

    std::vector<Detection> raw;
    Scanner scanner(g_patterns);
    scanner.SetExcludedTags(g_excludedTags);
    scanner.Scan(strings, filePath, ".dll",
        [&](const Detection& match) {
            Detection detection = match;
            detection.file = filePath;
            detection.container = container;
            detection.hash = hash;
            detection.fingerprint = hash;
            detection.lineNumber = 0;
            detection.contextStart = 0;
            raw.push_back(detection);
        },
        [&](const std::string& patternId, const std::string& detail) {
            g_skipped.Add(SkipReason::PatternLimit, filePath, patternId + ": " + detail);
        });

    PublishFileDetections(raw, filePath, scope);
}

void ProcessBinaryModule(const fs::path& path) {
    const std::string filePath = NormalizedPath(path);

    std::error_code ec;
    const uintmax_t rawSize = fs::file_size(path, ec);
    if (ec) {
        g_skipped.Add(SkipReason::Unreadable, filePath, ec.message());
        return;
    }

    const bool tooLarge = static_cast<int64_t>(rawSize) > kMaxScanBytes;
    std::string content;
    std::string hash;
    if (tooLarge) {
        hash = HashFile(path);
    }
    else {
        std::ifstream input(path, std::ios::binary);
        if (input.is_open()) {
            content.resize(static_cast<size_t>(rawSize));
            if (rawSize == 0 || input.read(content.data(), static_cast<std::streamsize>(rawSize))) {
                hash = SHA256::Hash(content);
            }
        }
    }
    if (hash.empty()) {
        g_skipped.Add(SkipReason::Unreadable, filePath, "could not read binary module");
        return;
    }

    const std::string scope = CompositeScope(path, g_scanRoot);
    g_filesProcessed++;

    if (CheckKnownBadHash(filePath, hash, scope)) return;
    if (g_whitelist.IsFileWhitelisted(filePath, hash)) {
        g_whitelistedFiles++;
        return;
    }

    if (GMAReader::IsBinaryModuleName(filePath)) {
        ReportBinaryModule(filePath, hash, scope, "");
    }

    if (tooLarge) {
        g_skipped.Add(SkipReason::TooLarge, filePath,
                      std::to_string(rawSize / (1024 * 1024)) + " MB, strings not read");
        return;
    }

    ScanModuleStrings(content, filePath, scope, "", hash);
}

void ReportUnsafeArchiveName(const std::string& entryPath, const std::string& rawName,
                             const std::string& scope) {
    Detection detection;
    detection.file = entryPath;
    detection.container = scope;
    detection.detection = "[CRITICAL] GMA-001 Archive Entry Escapes Its Archive";
    detection.severity = "critical";
    detection.id = "GMA-001";
    detection.lineNumber = 0;
    detection.lineText = sanitizeForReport("Entry name: " + rawName, 200);
    detection.hint =
        "A file inside this archive is named so that it appears to live somewhere else: it uses .. , "
        "a leading slash or a drive letter. Garry's Mod never produces such an archive. The name is a "
        "way to make the file look like it belongs to a different addon, which can put it past a "
        "whitelist entry written for that addon. The file has still been scanned, under its real "
        "location inside the archive.";
    detection.fingerprint = SHA256::Hash(rawName);

    NoteScanDetection(detection, scope);
    if (ReportDetection(detection)) {

    }
}

std::string RuleTitle(const std::string& definition) {
    const size_t bracket = definition.find("] ");
    std::string rest = bracket == std::string::npos ? definition : definition.substr(bracket + 2);
    const size_t space = rest.find(' ');
    if (space == std::string::npos) return rest;
    return rest.substr(space + 1);
}

int SeverityOrder(const std::string& severity) {
    if (severity == "critical") return 0;
    if (severity == "high") return 1;
    if (severity == "medium") return 2;
    return 3;
}

std::string RelativeToRoot(const std::string& file) {
    const std::string root = NormalizedPath(g_scanRoot);
    if (root.empty() || file.size() <= root.size()) return file;
    if (file.compare(0, root.size(), root) != 0) return file;
    size_t start = root.size();
    while (start < file.size() && (file[start] == '/' || file[start] == '\\')) start++;
    return file.substr(start);
}

std::string Elide(const std::string& text, size_t limit) {
    if (text.size() <= limit) return text;
    return text.substr(0, limit - 3) + "...";
}

void PrintFindings(const std::vector<Detection>& findings, const SeverityTotals& totals) {
    if (g_quietMode || findings.empty()) return;

    std::vector<const Detection*> ordered;
    ordered.reserve(findings.size());
    for (const Detection& detection : findings) ordered.push_back(&detection);
    std::stable_sort(ordered.begin(), ordered.end(), [](const Detection* a, const Detection* b) {
        const int left = SeverityOrder(a->severity);
        const int right = SeverityOrder(b->severity);
        if (left != right) return left < right;
        if (a->file != b->file) return a->file < b->file;
        return a->lineNumber < b->lineNumber;
    });

    const size_t shown = std::min<size_t>(ordered.size(), kMaxConsoleFindings);
    size_t printed = 0;
    std::string lastFile;

    std::cout << std::endl;
    for (size_t i = 0; i < ordered.size() && printed < shown; ++i) {
        const Detection& detection = *ordered[i];
        if (SeverityOrder(detection.severity) > kConsoleSeverityFloor &&
            printed >= kMinConsoleFindings) {
            break;
        }

        const std::string file = RelativeToRoot(detection.file);
        if (file != lastFile) {
            if (!lastFile.empty()) std::cout << std::endl;
            std::cout << con::Bold(file) << std::endl;
            lastFile = file;
        }

        std::string location = detection.lineNumber > 0
            ? ":" + std::to_string(detection.lineNumber)
            : std::string();

        std::cout << "  " << con::Badge(detection.severity) << " "
                  << con::SeverityText(detection.severity, detection.id) << con::Dim(location)
                  << "  " << con::Dim(Elide(RuleTitle(detection.detection), 62)) << std::endl;

        const std::string code = TrimAscii(detection.lineText);
        if (!code.empty()) {
            std::cout << "           " << con::Grey(Elide(code, 96)) << std::endl;
        }
        if (!detection.decodedContent.empty()) {
            std::cout << "           " << con::Blue("decoded: " + Elide(detection.decodedContent, 84)) << std::endl;
        }
        printed++;
    }

    const size_t hidden = ordered.size() - printed;
    if (hidden > 0) {
        std::cout << std::endl
                  << con::Dim("  " + std::to_string(hidden) + " further finding" +
                              (hidden == 1 ? " is" : "s are") + " in the report.")
                  << std::endl;
    }
    (void)totals;
}

void ReportComposite(const CompositeRule& rule, const std::string& filePath,
                     const CompositeEvidence& evidence, const std::string& container) {
    std::set<std::string> referenced;
    rule.expression.CollectIds(referenced);
    Detection detection;
    detection.file = filePath;
    detection.container = container;
    detection.detection = rule.definition;
    detection.severity = rule.severity;
    detection.id = rule.id;
    detection.hint = rule.hint;
    detection.lineText = "Combines: ";
    std::string fingerprint;
    for (const std::string& id : referenced) {
        const auto found = evidence.find(id);
        if (found == evidence.end()) continue;
        if (!detection.related.empty()) detection.lineText += ", ";
        detection.lineText += id;
        for (const auto& file : found->second) {
            const DetectionEvidence& item = file.second;
            detection.related.push_back(item);
            fingerprint += id + "\n" + item.file + "\n" + item.hash + "\n";
        }
    }
    detection.fingerprint = SHA256::Hash(fingerprint);
    if (ReportDetection(detection)) {
        g_compositeHits++;

    }
}

void EvaluateComposites(const std::string& filePath, const CompositeEvidence& evidence,
                        const std::string& container) {
    for (const CompositeRule* rule : g_composites.Match(EvidenceCounts(evidence), false)) {
        ReportComposite(*rule, filePath, evidence, container);
    }
}

void EvaluateScanComposites() {
    for (const auto& scope : g_scopeEvidence) {
        for (const CompositeRule* rule : g_composites.Match(EvidenceCounts(scope.second), true)) {
            ReportComposite(*rule, scope.first, scope.second, "");
        }
    }
}

void PublishFileDetections(const std::vector<Detection>& raw, const std::string& filePath,
                           const std::string& scope) {
    CompositeEvidence found;
    for (const Detection& detection : raw) {
        if (found[detection.id].empty()) {
            found[detection.id][filePath] = { detection.id, filePath, detection.lineNumber, detection.fingerprint };
        }
        NoteScanDetection(detection, scope);
        ReportDetection(detection);
    }
    EvaluateComposites(filePath, found, raw.empty() ? std::string() : raw.front().container);
}

bool ScanBuffer(const std::string& content, const std::string& filePath, const std::string& extension,
                const std::string& scope, const std::string& container,
                ScanCacheEntry* collected = nullptr) {
    const std::string hash = SHA256::Hash(content);
    const std::string& whitelistPath = container.empty() ? filePath : container;

    const bool knownBad = CheckKnownBadHash(filePath, hash, scope, container);
    if (!knownBad && g_whitelist.IsFileWhitelisted(whitelistPath, hash)) {
        g_whitelistedFiles++;
        return false;
    }

    bool problemRecorded = false;
    std::vector<Detection> raw;

    auto keep = [&](const Detection& match) {
        Detection detection = match;
        detection.file = filePath;
        detection.container = container;
        detection.hash = hash;
        detection.fingerprint = hash;
        raw.push_back(detection);
    };

    Scanner scanner(g_patterns);
    scanner.SetExcludedTags(g_excludedTags);
    scanner.Scan(content, filePath, extension, keep,
        [&](const std::string& patternId, const std::string& detail) {
            if (problemRecorded) return;
            problemRecorded = true;
            g_skipped.Add(SkipReason::PatternLimit, filePath, patternId + ": " + detail);
        });

    CollectStructuralSignals(content, extension, keep);

    PublishFileDetections(raw, filePath, scope);
    if (collected != nullptr) {
        collected->hash = hash;
        collected->detections = std::move(raw);
    }
    return !problemRecorded;
}

int64_t ModificationTime(const fs::path& path) {
    std::error_code ec;
    const auto written = fs::last_write_time(path, ec);
    if (ec) return 0;
    return static_cast<int64_t>(written.time_since_epoch().count());
}

void ProcessFile(const fs::path& filePath) {
    std::error_code ec;
    const uintmax_t rawSize = fs::file_size(filePath, ec);
    if (ec) {
        g_skipped.Add(SkipReason::Unreadable, NormalizedPath(filePath), ec.message());
        return;
    }

    if (static_cast<int64_t>(rawSize) > kMaxScanBytes) {
        g_skipped.Add(SkipReason::TooLarge, NormalizedPath(filePath),
                      std::to_string(rawSize / (1024 * 1024)) + " MB");
        return;
    }

    const std::string normalized = NormalizedPath(filePath);

    std::ifstream inFile(filePath, std::ios::binary);
    if (!inFile.is_open()) {
        g_skipped.Add(SkipReason::Unreadable, normalized, "could not open");
        return;
    }

    std::string content;
    content.resize(static_cast<size_t>(rawSize));
    if (rawSize > 0 && !inFile.read(content.data(), static_cast<std::streamsize>(rawSize))) {
        g_skipped.Add(SkipReason::Unreadable, NormalizedPath(filePath), "incomplete file read");
        return;
    }
    inFile.close();

    g_filesProcessed++;

    const std::string scope = CompositeScope(filePath, g_scanRoot);
    if (g_cache) {
        const std::string hash = SHA256::Hash(content);
        const ScanCacheEntry* cached = g_cache->Lookup(normalized, hash);
        if (cached != nullptr) {
            g_cache->NoteHit();
            if (!CheckKnownBadHash(normalized, hash, scope, "")) {
                if (g_whitelist.IsFileWhitelisted(normalized, hash)) g_whitelistedFiles++;
                else PublishFileDetections(cached->detections, normalized, scope);
            }
            g_cache->Store(normalized, *cached);
            return;
        }
    }

    ScanCacheEntry produced;
    const bool cacheable = ScanBuffer(content, normalized, ToLowerAscii(PathToUtf8(filePath.extension())),
                                      scope, "", g_cache ? &produced : nullptr);

    if (g_cache && cacheable) {
        produced.size = rawSize;
        produced.modified = ModificationTime(filePath);
        g_cache->Store(normalized, std::move(produced));
    }
}

void ScanArchiveEntries(std::istream& stream, int64_t totalSize,
                        const std::string& basePath, int depth);

void ProcessGMAFile(const fs::path& gmaPath) {
    const std::string gmaBasePath = NormalizedPath(gmaPath);

    std::ifstream file(gmaPath, std::ios::binary);
    if (!file.is_open()) {
        g_skipped.Add(SkipReason::Unreadable, gmaBasePath, "could not open");
        return;
    }

    std::error_code ec;
    const uintmax_t rawSize = fs::file_size(gmaPath, ec);
    if (ec) {
        g_skipped.Add(SkipReason::Unreadable, gmaBasePath, ec.message());
        return;
    }

    char magic[4] = {};
    file.read(magic, 4);
    const bool plain = file.good() && std::string(magic, 4) == "GMAD";
    file.clear();
    file.seekg(0);

    std::unique_ptr<MemoryBudget::Reservation> reservation;
    std::string decompressed;
    std::unique_ptr<MemoryStream> memory;
    std::istream* stream = &file;
    int64_t totalSize = static_cast<int64_t>(rawSize);

    if (!plain) {
        if (static_cast<int64_t>(rawSize) > kMaxArchiveBytes) {
            g_skipped.Add(SkipReason::TooLarge, gmaBasePath,
                          std::to_string(rawSize / (1024 * 1024)) + " MB compressed");
            return;
        }

        std::string headerBytes(lzma::kHeaderSize, '\0');
        if (!file.read(headerBytes.data(), static_cast<std::streamsize>(headerBytes.size()))) {
            g_skipped.Add(SkipReason::Malformed, gmaBasePath, "truncated compression header");
            return;
        }
        lzma::Header header;
        if (!lzma::ParseHeader(headerBytes, header)) {
            g_skipped.Add(SkipReason::Malformed, gmaBasePath, "invalid compression header");
            return;
        }
        constexpr uint64_t decoderAllowance = 16ull * 1024 * 1024;
        const uint64_t budget = g_archiveMemory->Capacity();
        if (rawSize + decoderAllowance >= budget) {
            g_skipped.Add(SkipReason::TooLarge, gmaBasePath, "compressed input exceeds archive memory budget");
            return;
        }
        uint64_t outputLimit = std::min<uint64_t>(kMaxArchiveBytes, budget - rawSize - decoderAllowance);
        if (header.sizeKnown) {
            if (header.uncompressedSize > outputLimit) {
                g_skipped.Add(SkipReason::TooLarge, gmaBasePath, "decompressed size exceeds archive memory budget or size limit");
                return;
            }
            outputLimit = header.uncompressedSize;
        }

        uint64_t attempt = outputLimit;
        if (!header.sizeKnown) {
            attempt = std::min<uint64_t>(outputLimit,
                std::max<uint64_t>(kDecompressGuessFloor, rawSize * kDecompressGuessRatio));
        }

        reservation = std::make_unique<MemoryBudget::Reservation>(
            *g_archiveMemory, rawSize + attempt + decoderAllowance);
        file.clear();
        file.seekg(0);
        std::string raw(static_cast<size_t>(rawSize), '\0');
        if (!file.read(raw.data(), static_cast<std::streamsize>(rawSize))) {
            g_skipped.Add(SkipReason::Unreadable, gmaBasePath, "incomplete compressed archive read");
            return;
        }

        lzma::Status status = lzma::Status::LimitReached;
        while (true) {
            decompressed.clear();
            decompressed.shrink_to_fit();
            decompressed.reserve(static_cast<size_t>(attempt));
            status = lzma::Decompress(raw, attempt, decompressed);
            if (status != lzma::Status::LimitReached || attempt >= outputLimit) break;
            attempt = std::min<uint64_t>(outputLimit, attempt * kDecompressGuessGrowth);
            reservation->Resize(rawSize + attempt + decoderAllowance);
        }

        if (status != lzma::Status::Ok) {
            g_skipped.Add(status == lzma::Status::LimitReached ? SkipReason::TooLarge : SkipReason::Compressed,
                          gmaBasePath, lzma::StatusText(status));
            return;
        }
        if (decompressed.compare(0, 4, "GMAD") != 0) {
            g_skipped.Add(SkipReason::Malformed, gmaBasePath, "decompressed data is not a GMA archive");
            return;
        }

        memory = std::make_unique<MemoryStream>(decompressed);
        stream = memory.get();
        totalSize = static_cast<int64_t>(decompressed.size());
        g_decompressedArchives++;
    }

    ScanArchiveEntries(*stream, totalSize, gmaBasePath, 0);
}

void ScanArchiveEntries(std::istream& stream, int64_t totalSize,
                        const std::string& basePath, int depth) {
    const GMAInfo info = GMAReader::ReadGMAInfo(stream, totalSize);
    if (!info.valid) {
        g_skipped.Add(SkipReason::Malformed, basePath, info.error);
        return;
    }

    for (const auto& entry : info.files) {
        bool unsafeName = false;
        const std::string safeName = GMAReader::SanitizeEntryName(entry.filename, unsafeName);
        const std::string entryPath = basePath + "/" + safeName;

        if (unsafeName) ReportUnsafeArchiveName(entryPath, entry.filename, basePath);

        const bool module = GMAReader::IsBinaryModuleName(safeName) ||
                            GMAReader::IsNativeBinaryName(safeName);
        const bool archive = GMAReader::IsArchiveFile(safeName);
        if (!module && !archive && !GMAReader::IsScannableFile(safeName)) continue;

        if (entry.size > kMaxScanBytes) {
            g_skipped.Add(SkipReason::TooLarge, entryPath,
                          std::to_string(entry.size / (1024 * 1024)) + " MB");
            continue;
        }

        const std::string content = GMAReader::ExtractFileContent(stream, entry, info.contentOffset, kMaxScanBytes);
        if (content.empty() && entry.size != 0) {
            g_skipped.Add(SkipReason::Unreadable, entryPath, "could not extract from archive");
            continue;
        }

        if (archive) {
            if (depth >= kMaxArchiveDepth) {
                g_skipped.Add(SkipReason::TooLarge, entryPath, "archives nested more than "
                              + std::to_string(kMaxArchiveDepth) + " deep");
                continue;
            }
            if (content.compare(0, 4, "GMAD") != 0) {
                g_skipped.Add(SkipReason::Compressed, entryPath,
                              "compressed archive inside an archive");
                continue;
            }
            g_filesProcessed++;
            MemoryStream nested(content);
            ScanArchiveEntries(nested, static_cast<int64_t>(content.size()), entryPath, depth + 1);
            continue;
        }

        const std::string hash = SHA256::Hash(content);
        if (module) {
            g_filesProcessed++;
            if (CheckKnownBadHash(entryPath, hash, basePath, basePath)) continue;
            if (g_whitelist.IsFileWhitelisted(basePath, hash)) {
                g_whitelistedFiles++;
                continue;
            }
            if (GMAReader::IsBinaryModuleName(safeName)) {
                ReportBinaryModule(entryPath, hash, basePath, basePath);
            }
            ScanModuleStrings(content, entryPath, basePath, basePath, hash);
            continue;
        }

        g_filesProcessed++;
        ScanBuffer(content, entryPath, GMAReader::GetExtension(safeName), basePath, basePath);
    }
}

void PauseIfInteractive() {
    if (!g_interactive) return;
    std::cout << "Press Enter to exit...";
    std::cin.get();
}

int Fail(const std::string& message) {
    std::cerr << "Error: " << message << std::endl;
    PauseIfInteractive();
    return kExitError;
}

size_t EditDistance(const std::string& a, const std::string& b) {
    std::vector<size_t> previous(b.size() + 1);
    std::vector<size_t> current(b.size() + 1);
    for (size_t j = 0; j <= b.size(); ++j) previous[j] = j;
    for (size_t i = 1; i <= a.size(); ++i) {
        current[0] = i;
        for (size_t j = 1; j <= b.size(); ++j) {
            const size_t cost = a[i - 1] == b[j - 1] ? 0 : 1;
            current[j] = std::min(std::min(current[j - 1] + 1, previous[j] + 1), previous[j - 1] + cost);
        }
        previous = current;
    }
    return previous[b.size()];
}

std::set<std::string> LoadedRuleIds() {
    std::set<std::string> ids{ "HASH-001", "MOD-001", "GMA-001" };
    for (const StructuralSignal& signal : StructuralSignals()) ids.insert(signal.id);
    for (const std::string& id : g_patterns.Ids()) ids.insert(id);
    for (const CompositeRule& rule : g_composites.Rules()) {
        if (!rule.id.empty()) ids.insert(rule.id);
    }
    return ids;
}

void WarnAboutUnknownWhitelistIds() {
    static const std::regex looksLikeId(R"([A-Z]{2,6}-[0-9]{1,4})");

    const std::set<std::string> known = LoadedRuleIds();
    std::vector<std::string> suspect;
    for (const Whitelist::Entry& entry : g_whitelist.PathRules()) {
        const size_t separator = entry.text.find(";;;");
        if (separator == std::string::npos) continue;
        const std::string substring = TrimAscii(entry.text.substr(separator + 3));
        if (substring.empty()) continue;
        if (!std::regex_match(substring, looksLikeId)) continue;
        if (known.count(substring) > 0) continue;
        suspect.push_back(entry.text);
    }
    if (suspect.empty()) return;

    std::cerr << std::endl;
    std::cerr << "Warning: " << suspect.size() << " whitelist rule"
              << (suspect.size() == 1 ? "" : "s") << " name a rule id that does not exist:"
              << std::endl;
    for (size_t i = 0; i < suspect.size() && i < kSkipSamplesInSummary; ++i) {
        std::cerr << "    " << suspect[i] << std::endl;
    }
    if (suspect.size() > kSkipSamplesInSummary) {
        std::cerr << "    ... and " << (suspect.size() - kSkipSamplesInSummary) << " more" << std::endl;
    }
    std::cerr << "The field after ;;; is matched as a substring of the finding text, so a"
              << std::endl
              << "shortened id such as LUA-1 silently suppresses LUA-121 as well. Write the"
              << std::endl
              << "id in full, or use --accept, which checks it." << std::endl;
}

void WarnAboutWhitelistedKnownBad() {
    std::vector<std::string> conflicting;
    for (const std::string& hash : g_whitelist.Hashes()) {
        if (g_knownBadHashes.find(hash) != g_knownBadHashes.end()) conflicting.push_back(hash);
    }
    if (conflicting.empty()) return;

    std::cerr << std::endl;
    std::cerr << "Warning: " << conflicting.size() << " whitelist entr"
              << (conflicting.size() == 1 ? "y names a hash" : "ies name hashes")
              << " that known_hashes.txt lists as a backdoor:" << std::endl;
    for (size_t i = 0; i < conflicting.size() && i < kSkipSamplesInSummary; ++i) {
        std::cerr << "    " << conflicting[i] << std::endl;
    }
    if (conflicting.size() > kSkipSamplesInSummary) {
        std::cerr << "    ... and " << (conflicting.size() - kSkipSamplesInSummary) << " more" << std::endl;
    }
    std::cerr << "The whitelist is for false positives, and a published backdoor hash is not"
              << std::endl
              << "one, so those files are reported anyway. Remove the whitelist entry once you"
              << std::endl
              << "have dealt with the file." << std::endl;
}

void WarnAboutUnreachableComposites() {
    if (g_excludedTags.empty() || g_composites.Count() == 0) return;

    std::map<std::string, int> available;
    for (const std::string& id : g_patterns.Ids()) {
        const Pattern* pattern = g_patterns.ById(id);
        if (pattern == nullptr) continue;
        bool excluded = false;
        for (const std::string& tag : pattern->tags) {
            if (g_excludedTags.count(tag) > 0) { excluded = true; break; }
        }
        if (!excluded) available[id] = 1;
    }

    std::set<std::string> reachable;
    for (bool scanLevel : { false, true }) {
        for (const CompositeRule* rule : g_composites.Match(available, scanLevel)) {
            reachable.insert(rule->id);
        }
    }

    std::vector<std::string> lost;
    for (const CompositeRule& rule : g_composites.Rules()) {
        if (!rule.id.empty() && reachable.count(rule.id) == 0) {
            lost.push_back(rule.id + "  " + rule.severity);
        }
    }
    if (lost.empty()) return;

    std::cerr << std::endl;
    std::cerr << "Warning: --exclude-tags leaves " << lost.size() << " composite rule"
              << (lost.size() == 1 ? "" : "s") << " that can no longer fire:" << std::endl;
    for (size_t i = 0; i < lost.size() && i < kSkipSamplesInSummary; ++i) {
        std::cerr << "    " << lost[i] << std::endl;
    }
    if (lost.size() > kSkipSamplesInSummary) {
        std::cerr << "    ... and " << (lost.size() - kSkipSamplesInSummary) << " more" << std::endl;
    }
    std::cerr << "A composite carries no tags of its own; it fires on what the excluded rules"
              << std::endl
              << "would have found. Excluding a noisy tag can therefore drop a critical verdict"
              << std::endl
              << "that has nothing to do with that tag." << std::endl;
}

std::set<std::string> KnownRuleIds(const fs::path& ruleDir) {
    std::set<std::string> ids{ "HASH-001", "MOD-001", "GMA-001" };
    for (const StructuralSignal& signal : StructuralSignals()) ids.insert(signal.id);

    PatternSet patterns;
    if (patterns.LoadFromDirectory(ruleDir)) {
        for (const std::string& id : patterns.Ids()) ids.insert(id);

        CompositeRuleSet composites;
        composites.Load(ResolveDataFile(ruleDir, "composite_rules.txt"), patterns);
        for (const CompositeRule& rule : composites.Rules()) {
            if (!rule.id.empty()) ids.insert(rule.id);
        }
    }
    return ids;
}

bool IsSafeDownloadUrl(const std::string& url) {
    if (url.rfind("https://", 0) != 0) return false;
    if (url.size() > 2048) return false;
    for (char c : url) {
        const unsigned char value = static_cast<unsigned char>(c);
        if (value <= 0x20 || value >= 0x7f) return false;
        if (c == '"' || c == '\'' || c == '\\' || c == '&' || c == '|' ||
            c == '<' || c == '>' || c == '^' || c == '`' || c == '$') {
            return false;
        }
    }
    return true;
}

std::string ShellQuote(const fs::path& path) {
    return "\"" + NormalizedPath(path) + "\"";
}

struct WorkshopItem {
    std::string title;
    uint64_t size = 0;
    std::string fileUrl;
    bool known = false;
};

WorkshopItem AskSteamAboutItem(const std::string& id, const fs::path& work) {
    WorkshopItem item;
    if (std::system(nullptr) == 0) return item;

    const fs::path metaPath = work / "item.json";
    const std::string command =
        "curl -sS -f -o " + ShellQuote(metaPath) +
        " -d itemcount=1 -d \"publishedfileids[0]=" + id + "\"" +
        " https://api.steampowered.com/ISteamRemoteStorage/GetPublishedFileDetails/v1/";
    if (std::system(command.c_str()) != 0) return item;

    try {
        std::ifstream input(metaPath, std::ios::binary);
        if (!input) return item;
        json response;
        input >> response;
        const auto& details = response.at("response").at("publishedfiledetails").at(0);
        if (details.value("result", 0) != 1) return item;
        item.title = details.value("title", "");
        item.fileUrl = details.value("file_url", "");
        const json& size = details.contains("file_size") ? details.at("file_size") : json();
        if (size.is_string()) item.size = std::strtoull(size.get<std::string>().c_str(), nullptr, 10);
        else if (size.is_number_unsigned()) item.size = size.get<uint64_t>();
        item.known = true;
    }
    catch (const std::exception&) {
        return WorkshopItem();
    }
    return item;
}

fs::path LocalWorkshopCopy(const std::string& id) {
    std::vector<fs::path> roots;
    for (const char* name : { "STEAM_PATH", "STEAMPATH", "ProgramFiles(x86)", "ProgramFiles" }) {
        const std::string value = con::EnvValue(name);
        if (!value.empty()) roots.push_back(fs::path(value));
    }
    roots.push_back("C:/Program Files (x86)/Steam");
    roots.push_back("C:/Steam");

    const std::string home = con::EnvValue("HOME");
    if (!home.empty()) {
        roots.push_back(fs::path(home) / ".steam" / "steam");
        roots.push_back(fs::path(home) / ".local" / "share" / "Steam");
        roots.push_back(fs::path(home) / "Library" / "Application Support" / "Steam");
    }

    std::error_code ec;
    for (const fs::path& root : roots) {
        for (const fs::path& base : { root, root / "Steam" }) {
            const fs::path candidate = base / "steamapps" / "workshop" / "content" / "4000" / id;
            if (fs::is_directory(candidate, ec) && !ec) return candidate;
        }
    }
    return fs::path();
}

int FetchWorkshopItem(const std::string& id, fs::path& downloaded) {
    std::error_code ec;
    const fs::path work = fs::temp_directory_path(ec) / ("bdscan_workshop_" + id);
    if (ec) return Fail("Could not locate a temporary directory: " + ec.message());
    fs::create_directories(work, ec);
    if (ec) return Fail("Could not create " + NormalizedPath(work) + ": " + ec.message());

    const WorkshopItem item = AskSteamAboutItem(id, work);
    if (item.known && !item.title.empty()) {
        std::cout << "  " << con::Bold(item.title) << std::endl;
        if (item.size > 0) {
            std::cout << "  " << con::Dim(std::to_string(item.size / 1024) + " KiB") << std::endl;
        }
    }

    const fs::path local = LocalWorkshopCopy(id);
    if (!local.empty()) {
        std::cout << "  " << con::Dim("Already subscribed; reading " + NormalizedPath(local))
                  << std::endl << std::endl;
        downloaded = local;
        return kExitClean;
    }

    if (!item.fileUrl.empty()) {
        if (!IsSafeDownloadUrl(item.fileUrl)) {
            return Fail("Steam returned a download URL this refuses to pass to curl: " + item.fileUrl);
        }
        const fs::path gmaPath = work / (id + ".gma");
        const std::string command =
            "curl -sS -f -L -o " + ShellQuote(gmaPath) + " \"" + item.fileUrl + "\"";
        std::cout << "  " << con::Dim("Downloading ...") << std::endl;
        if (std::system(command.c_str()) != 0) {
            return Fail("curl could not download the item from " + item.fileUrl);
        }
        if (!fs::is_regular_file(gmaPath, ec) || ec) {
            return Fail("The download produced no file at " + NormalizedPath(gmaPath));
        }
        std::cout << "  " << con::Dim("Saved to " + NormalizedPath(gmaPath)) << std::endl << std::endl;
        downloaded = gmaPath;
        return kExitClean;
    }

    const fs::path target = work / "steamapps" / "workshop" / "content" / "4000" / id;
    if (std::system(nullptr) != 0) {
#ifdef _WIN32
        const std::string quiet = " 2>NUL";
#else
        const std::string quiet = " 2>/dev/null";
#endif
        const std::string command =
            "steamcmd +force_install_dir " + ShellQuote(work) +
            " +login anonymous +workshop_download_item 4000 " + id + " +quit" + quiet;
        std::cout << "  " << con::Dim("Asking steamcmd to download it ...") << std::endl;
        if (std::system(command.c_str()) == 0 && fs::is_directory(target, ec) && !ec) {
            std::cout << "  " << con::Dim("Saved to " + NormalizedPath(target))
                      << std::endl << std::endl;
            downloaded = target;
            return kExitClean;
        }
    }

    if (!item.known) {
        return Fail("Could not reach the Steam API for item " + id + ". Check the id and that "
                    "curl is installed, or download the item yourself and scan it with -d.");
    }
    return Fail("Steam publishes no direct download for item " + id + ", and steamcmd is not "
                "available here. Garry's Mod items are served through Steam itself, so use\n"
                "    steamcmd +force_install_dir <dir> +login anonymous "
                "+workshop_download_item 4000 " + id + " +quit\n"
                "and point -d at <dir>. Subscribing to the item in Garry's Mod also works: this "
                "finds an already downloaded copy on its own.");
}


fs::path ResolveRuleBase(const ScanOptions& options, int argc, const NativeChar* argv[]) {
    if (!options.ruleDir.empty()) return options.ruleDir;
    if (argc > 0 && argv[0] != nullptr) {
        std::error_code ec;
        const fs::path exePath = fs::absolute(fs::path(argv[0]), ec);
        if (!ec) {
            const fs::path exeDir = exePath.parent_path();
            if (fs::is_regular_file(exeDir / "lua_patterns.txt", ec)) return exeDir;
        }
    }
    return fs::current_path();
}

int PrintVersion(const ScanOptions& options, int argc, const NativeChar* argv[]) {
    std::cout << "BD-Scan " << kScannerVersion << std::endl;

    const fs::path ruleBase = ResolveRuleBase(options, argc, argv);
    PatternSet patterns;
    if (!patterns.LoadFromDirectory(ruleBase)) {
        std::cout << "rules    not found in " << NormalizedPath(ruleBase) << std::endl;
        return kExitClean;
    }

    CompositeRuleSet composites;
    composites.Load(ResolveDataFile(ruleBase, "composite_rules.txt"), patterns);

    std::cout << "rules    " << patterns.Count() << " patterns, "
              << composites.Count() << " composite rules" << std::endl;
    std::cout << "digest   "
              << SHA256::Hash(patterns.RawContent() + composites.RawContent()).substr(0, 12) << std::endl;
    std::cout << "from     " << NormalizedPath(ruleBase) << std::endl;
    return kExitClean;
}

int AcceptFinding(const ScanOptions& options, const fs::path& ruleDir) {
    const std::string& entry = options.accept;
    const size_t at = entry.find('@');
    std::string rule = at == std::string::npos ? entry : entry.substr(0, at);
    std::string glob = at == std::string::npos ? std::string() : entry.substr(at + 1);

    rule = TrimAscii(rule);
    glob = TrimAscii(glob);

    if (rule.empty()) return Fail("--accept needs a rule id, for example LUA-153@*/myaddon/*");

    const std::string* const fields[] = { &rule, &glob, &options.reason };
    for (const std::string* field : fields) {
        if (field->find(";;;") != std::string::npos) {
            return Fail("--accept and --reason cannot contain ';;;'. That sequence separates the "
                        "fields of whitelist.txt, and a value holding one would be written as a "
                        "different rule from the one you asked for.");
        }
        for (char c : *field) {
            if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) {
                return Fail("--accept and --reason cannot contain line breaks or control "
                            "characters. One entry is one line of whitelist.txt.");
            }
        }
    }

    const bool hash = rule.size() == 64 &&
        std::all_of(rule.begin(), rule.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
    if (!hash && glob.empty()) {
        return Fail("--accept needs a path after the @, for example " + rule + "@*/myaddon/*");
    }

    if (!hash) {
        const std::set<std::string> known = KnownRuleIds(ruleDir);
        if (known.empty()) {
            return Fail("Could not read the rules, so " + rule + " cannot be checked. "
                        "Point --rules at the directory holding lua_patterns.txt.");
        }
        if (known.count(rule) == 0) {
            std::string closest;
            size_t best = 3;
            const std::string upper = ToUpperAscii(rule);
            for (const std::string& candidate : known) {
                const size_t distance = EditDistance(upper, candidate);
                if (distance < best) { best = distance; closest = candidate; }
            }
            std::string message = "No rule called " + rule + ".";
            if (!closest.empty()) message += " Did you mean " + closest + "?";
            else message += " Rule ids look like LUA-153, BIN-014 or COMP-002, and every finding prints its own.";
            return Fail(message);
        }
    }

    const fs::path target = ResolveDataFile(ruleDir, "whitelist.txt");
    std::ofstream out(target, std::ios::app);
    if (!out.is_open()) return Fail("Could not write " + NormalizedPath(target));

    const std::time_t now = std::time(nullptr);
    std::tm parts{};
#ifdef _WIN32
    localtime_s(&parts, &now);
#else
    localtime_r(&now, &parts);
#endif
    char stamp[16];
    std::strftime(stamp, sizeof(stamp), "%Y-%m-%d", &parts);

    out << "\n# reviewed " << stamp;
    if (!options.reason.empty()) out << ": " << options.reason;
    out << "\n";
    const std::string line = hash
        ? (glob.empty() ? ToLowerAscii(rule) : glob + ";;;" + ToLowerAscii(rule))
        : glob + ";;;" + rule;
    out << line << "\n";
    out.close();
    if (!out) return Fail("Could not write " + NormalizedPath(target));

    std::cout << con::Green("Recorded in " + NormalizedPath(target) + ":") << std::endl;
    std::cout << "  " << line << std::endl;
    if (options.reason.empty()) {
        std::cout << con::Dim("  No reason recorded. Use --reason, or the next person cannot") << std::endl;
        std::cout << con::Dim("  tell whether this entry is still justified.") << std::endl;
    }
    return kExitClean;
}

int RunScanApplication(int argc, const NativeChar* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    ScanOptions options;
    std::string argumentError;
    con::Configure(con::Mode::Auto);
    if (!ParseCommandLine(argc, argv, options, argumentError)) return Fail(argumentError);
    con::Configure(options.colour);
    if (options.help) { PrintUsage(); return kExitClean; }
    if (options.version) return PrintVersion(options, argc, argv);
    g_interactive = options.target.empty() && options.accept.empty() && options.workshop.empty();
    if (g_interactive) {
        std::cout << std::endl;
        std::cout << "  " << con::Bold("Which folder should be scanned?") << std::endl;
        std::cout << "  " << con::Dim("Usually the addons directory of a server:") << std::endl;
        std::cout << std::endl;
        std::cout << "      " << con::Blue("C:/srv/garrysmod/addons") << std::endl;
        std::cout << std::endl;
        std::cout << "  " << con::Dim("Dragging the folder onto this window pastes its path.") << std::endl;
        std::cout << "  " << con::Dim("An HTML report is written beside the executable.") << std::endl;
        std::cout << std::endl;
        std::cout << "  " << con::Bold("Folder") << con::Dim(" (-h for all options)") << ": " << std::flush;
        if (!ParseInteractiveLine(ReadInputLine(), options, argumentError)) return Fail(argumentError);
        if (options.help) { PrintUsage(); return kExitClean; }
        options.html = true;
    }
    g_ruleDir = options.ruleDir;
    if (!options.accept.empty()) {
        return AcceptFinding(options, ResolveRuleBase(options, argc, argv));
    }
    if (!options.workshop.empty()) {
        if (!options.target.empty()) {
            return Fail("Use either --workshop or -d, not both.");
        }
        fs::path downloaded;
        const int status = FetchWorkshopItem(options.workshop, downloaded);
        if (status != kExitClean) return status;
        options.target = downloaded;
    }
    if (options.target.empty()) return Fail("No path given.");

    {
        std::error_code ec;
        const bool looksLikeInstall =
            fs::is_directory(options.target / "addons", ec) &&
            fs::is_directory(options.target / "gamemodes" / "base", ec);
        if (looksLikeInstall && !options.quiet) {
            std::cout << std::endl;
            std::cout << "  " << con::Yellow("This looks like a whole Garry's Mod install.") << std::endl;
            std::cout << "  " << con::Dim("The stock game files contain RunString and a superadmin grant") << std::endl;
            std::cout << "  " << con::Dim("for legitimate reasons, so you will see a handful of CRITICAL") << std::endl;
            std::cout << "  " << con::Dim("findings that belong to the game. Scanning addons/ on its own") << std::endl;
            std::cout << "  " << con::Dim("gives a shorter list to act on.") << std::endl;
        }
    }
    g_minSeverity = options.minSeverity;
    g_excludedTags = options.excludedTags;
    g_quietMode = options.quiet;
    g_generateHtml = options.html;
    g_generateSarif = options.sarif;
    g_diffMode = options.diff;
    g_outputDir = ExtendedPath(options.outputDir);
    g_ruleDir = options.ruleDir;
    g_archiveMemory = std::make_unique<MemoryBudget>(options.archiveMemoryBytes);

    if (!g_quietMode) {
        const std::string title = std::string("GMod Backdoor Scanner v") + kScannerVersion;
        const std::string rule(60, '=');
        const std::string blank = "  ||" + std::string(56, ' ') + "||";
        std::cout << std::endl;
        std::cout << "  " << rule << std::endl;
        std::cout << blank << std::endl;
        std::cout << "  ||   " << title << std::string(53 - title.size(), ' ') << "||" << std::endl;
        std::cout << "  ||   Detect malicious code in Garry's Mod files           ||" << std::endl;
        std::cout << blank << std::endl;
        std::cout << "  " << rule << std::endl;
        std::cout << std::endl;
    }

    fs::path exeDir;
    if (argc > 0 && argv[0] != nullptr) {
        std::error_code ec;
        const fs::path exePath = fs::absolute(fs::path(argv[0]), ec);
        if (!ec) exeDir = exePath.parent_path();
    }
    if (!g_ruleDir.empty()) {
        std::error_code ec;
        if (!fs::is_directory(g_ruleDir, ec)) {
            return Fail("--rules is not a directory: " + PathToUtf8(g_ruleDir));
        }
        exeDir = g_ruleDir;
    }


    else {
        std::error_code ec;
        if (!fs::is_regular_file(exeDir / "lua_patterns.txt", ec) ||
            !fs::is_regular_file(exeDir / "binary_patterns.txt", ec)) exeDir = fs::current_path();
    }

    if (!g_patterns.LoadFromDirectory(exeDir)) {
        return Fail("Patterns could not be loaded. Please ensure the .txt files are present.");
    }
    if (!g_quietMode) {
        std::cout << "Loaded " << g_patterns.Count() << " patterns." << std::endl;
    }

    std::vector<std::string> rejectedHashes;
    const size_t hashCount = LoadHashList(ResolveDataFile(exeDir, "known_hashes.txt"),
                                          g_knownBadHashes, &rejectedHashes);
    if (hashCount > 0 && !g_quietMode) {
        std::cout << "Loaded " << hashCount << " known bad hash"
                  << (hashCount == 1 ? "" : "es") << "." << std::endl;
    }
    if (!rejectedHashes.empty()) {
        std::cerr << std::endl;
        std::cerr << "Warning: " << rejectedHashes.size() << " line"
                  << (rejectedHashes.size() == 1 ? "" : "s") << " in known_hashes.txt "
                  << (rejectedHashes.size() == 1 ? "is not a" : "are not") << " SHA-256:" << std::endl;
        for (size_t i = 0; i < rejectedHashes.size() && i < kSkipSamplesInSummary; ++i) {
            std::cerr << "    " << rejectedHashes[i] << std::endl;
        }
        if (rejectedHashes.size() > kSkipSamplesInSummary) {
            std::cerr << "    ... and " << (rejectedHashes.size() - kSkipSamplesInSummary)
                      << " more" << std::endl;
        }
        std::cerr << "A hash is 64 hexadecimal characters. Anything else can never match a file,"
                  << std::endl
                  << "and counting it would overstate how much this scan actually checked."
                  << std::endl;
    }

    g_whitelist.Load(ResolveDataFile(exeDir, "whitelist.txt"));
    if (!g_whitelist.Empty() && !g_quietMode) {
        std::cout << "Loaded whitelist: " << g_whitelist.RuleCount() << " rules, "
                  << g_whitelist.HashCount() << " hashes." << std::endl;
    }

    {
        const fs::path compositePath = ResolveDataFile(exeDir, "composite_rules.txt");
        std::error_code ec;
        const bool present = fs::exists(compositePath, ec);
        if (ec || (present && !g_composites.Load(compositePath, g_patterns))) {
            return Fail("Composite rules could not be loaded: " + PathToUtf8(compositePath));
        }
    }
    if (g_composites.Count() > 0 && !g_quietMode) {
        std::cout << "Loaded " << g_composites.Count() << " composite rules." << std::endl;
    }

    WarnAboutUnknownWhitelistIds();
    WarnAboutWhitelistedKnownBad();
    WarnAboutUnreachableComposites();

    g_rulesetVersion = SHA256::Hash(g_patterns.RawContent() + g_composites.RawContent()).substr(0, 12);
    {
        std::string policy;
        for (const char* name : { "known_hashes.txt", "whitelist.txt" }) {
            const fs::path path = ResolveDataFile(exeDir, name);
            std::error_code ec;
            const bool present = fs::exists(path, ec);
            if (ec) return Fail("Could not access " + PathToUtf8(path));
            if (present) {
                std::ifstream input(path, std::ios::binary);
                if (!input) return Fail("Could not read " + PathToUtf8(path));
                std::ostringstream buffer;
                buffer << input.rdbuf();
                if (input.bad()) return Fail("Incomplete read of " + PathToUtf8(path));
                policy += std::string(name) + "\n" + buffer.str() + "\n";
            }
        }
        g_policyVersion = SHA256::Hash(policy);
    }
    if (!g_quietMode) {
        std::cout << "Ruleset " << g_rulesetVersion << "." << std::endl;
    }

    {
        std::error_code ec;
        fs::create_directories(g_outputDir, ec);
        if (ec || !fs::is_directory(g_outputDir, ec)) {
            return Fail("Output directory is not usable: " + NormalizedPath(g_outputDir));
        }
    }

    const fs::path scanRoot = ExtendedPath(options.target);
    g_scanRoot = scanRoot;
    g_filter.SetMinSeverity(g_minSeverity);
    g_filter.SetWhitelist(&g_whitelist);

    if (!options.cacheFile.empty()) {
        g_cache = std::make_unique<ScanCache>();
        LoadScanCache(options.cacheFile);
        if (!g_quietMode && g_cache->LoadedCount() > 0) {
            std::cout << "Cache: " << g_cache->LoadedCount() << " files from the last run." << std::endl;
        }
    }

    if (g_diffMode) {
        g_filter.SetBaseline(LoadBaselineKeys(OutputPath("last_scan.json")));
        if (!g_quietMode) {
            if (g_filter.BaselineSize() > 0) {
                std::cout << "Diff mode: Comparing against " << g_filter.BaselineSize() << " previous detections." << std::endl;
            } else {
                std::cout << "Diff mode: No previous scan found, showing all detections." << std::endl;
            }
        }
    }

    bool singleFile = false;
    {
        std::error_code ec;
        if (fs::is_regular_file(scanRoot, ec) && !ec) singleFile = true;
        else if (!fs::is_directory(scanRoot, ec) || ec) {
            return Fail("Invalid or inaccessible path: " + NormalizedPath(scanRoot));
        }
    }
    if (!g_quietMode) {
        std::cout << (singleFile ? "Selected file: " : "Selected directory: ") << NormalizedPath(scanRoot) << std::endl << std::endl;
    }

    const auto startedAt = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const auto start = std::chrono::high_resolution_clock::now();

    std::set<std::string> scannableExtensions;
    for (const std::string& extension : g_patterns.Extensions()) scannableExtensions.insert(extension);
    scannableExtensions.insert(".gma");

    std::vector<fs::path> targets;
    if (singleFile) {
        targets.push_back(scanRoot);
    }
    else {
        targets = CollectScanTargets(scanRoot, [&](const fs::path& path) {
            const std::string extension = ToLowerAscii(PathToUtf8(path.extension()));
            if (scannableExtensions.count(extension) == 0) return IsBinaryModule(path);
            if (extension == ".txt" || extension == ".dat" || extension == ".json") {
                return GMAReader::IsRuntimeDataPath(NormalizedPath(path));
            }
            return true;
        }, g_skipped);
    }

    if (!g_quietMode) {
        std::cout << "Queued " << targets.size() << " files." << std::endl << std::endl;
    }

    {
        std::atomic<size_t> nextIndex{0};
        unsigned hardware = std::thread::hardware_concurrency();
        if (hardware == 0) hardware = 4;
        const std::string requested = EnvironmentValue("BDSCAN_THREADS");
        if (!requested.empty()) {
            const unsigned long chosen = std::strtoul(requested.c_str(), nullptr, 10);
            if (chosen > 0 && chosen <= 4096) hardware = static_cast<unsigned>(chosen);
        }
        const size_t workerCount = std::min<size_t>(hardware, std::max<size_t>(targets.size(), 1));

        std::vector<ScanWorker> workers;
        workers.reserve(workerCount);
        try {
            for (size_t w = 0; w < workerCount; ++w) {
                workers.emplace_back([&]() {
                    for (size_t i = nextIndex++; i < targets.size(); i = nextIndex++) {
                        const fs::path& path = targets[i];
                        ExecuteScanTask(path, g_skipped, [&]() {
                            if (IsBinaryModule(path)) ProcessBinaryModule(path);
                            else if (ToLowerAscii(PathToUtf8(path.extension())) == ".gma") ProcessGMAFile(path);
                            else ProcessFile(path);
                        });
                    }
                });
            }
        }
        catch (...) {
            for (auto& worker : workers) worker.Join();
            throw;
        }
        for (auto& worker : workers) worker.Join();
    }

    EvaluateScanComposites();

    const auto end = std::chrono::high_resolution_clock::now();
    const std::chrono::duration<double> duration = end - start;

    std::sort(g_reported.begin(), g_reported.end(), DetectionOrder);
    const std::vector<FileScore> scores = ComputeFileScores(g_reported);
    const SeverityTotals totals = TotalsOf(g_reported);
    const int whitelisted = g_filter.Count(Verdict::Whitelisted) + g_whitelistedFiles.load();

    json logJson = json::object();
    logJson["schema_version"] = 2;
    logJson["scan_root"] = NormalizedPath(scanRoot);
    logJson["complete"] = (g_skipped.Total() == 0);
    logJson["archive_memory_limit_bytes"] = g_archiveMemory->Capacity();
    logJson["archive_memory_peak_bytes"] = g_archiveMemory->Peak();
    logJson["start_time"] = startedAt;
    logJson["end_time"] = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    logJson["files_processed"] = g_filesProcessed.load();
    logJson["detections_found"] = g_detections.load();
    logJson["known_backdoors"] = g_knownBadMatched.size();
    logJson["decompressed_archives"] = g_decompressedArchives.load();
    logJson["composite_hits"] = g_compositeHits.load();
    logJson["whitelisted"] = whitelisted;
    logJson["min_severity"] = g_minSeverity;
    logJson["ruleset_version"] = g_rulesetVersion;
    logJson["policy_version"] = g_policyVersion;
    if (!g_excludedTags.empty()) {
        logJson["excluded_tags"] = std::vector<std::string>(g_excludedTags.begin(), g_excludedTags.end());
    }
    logJson["diff_mode"] = g_diffMode;
    if (g_diffMode) logJson["already_in_baseline"] = g_filter.Count(Verdict::InBaseline);
    logJson["statistics"] = {
        {"critical", totals.critical},
        {"high", totals.high},
        {"medium", totals.medium},
        {"low", totals.low}
    };

    {
        json unscanned = json::object();
        unscanned["total"] = g_skipped.Total();
        unscanned["by_reason"] = json::object();
        for (int i = 0; i < static_cast<int>(SkipReason::Count); ++i) {
            const SkipReason reason = static_cast<SkipReason>(i);
            unscanned["by_reason"][SkipReasonName(reason)] = g_skipped.Count(reason);
        }
        unscanned["list_truncated"] = g_skipped.Truncated();
        unscanned["files"] = json::array();
        for (const SkipRegistry::Entry& entry : g_skipped.Entries()) {
            unscanned["files"].push_back({
                {"file", entry.path},
                {"reason", SkipReasonName(entry.reason)},
                {"detail", entry.detail}
            });
        }
        logJson["unscanned"] = std::move(unscanned);
    }

    logJson["files"] = json::array();
    for (const FileScore& score : scores) {
        logJson["files"].push_back({
            {"file", score.file},
            {"score", score.score},
            {"detections", score.detections},
            {"distinct_types", score.distinctTypes},
            {"critical", score.critical},
            {"high", score.high},
            {"medium", score.medium},
            {"low", score.low}
        });
    }

    logJson["detections"] = json::array();
    for (const Detection& detection : g_reported) {
        json entry;
        entry["file"] = detection.file;
        entry["severity"] = detection.severity;
        entry["detection"] = detection.detection;
        if (!detection.id.empty()) entry["id"] = detection.id;
        if (!detection.hint.empty()) entry["hint"] = detection.hint;
        entry["line_number"] = detection.lineNumber;
        entry["line_text"] = detection.lineText;
        if (!detection.decodedContent.empty()) entry["decoded_content"] = detection.decodedContent;
        if (!detection.hash.empty()) entry["hash"] = detection.hash;
        entry["fingerprint"] = detection.fingerprint;
        if (!detection.related.empty()) {
            entry["related_findings"] = json::array();
            for (const DetectionEvidence& evidence : detection.related) {
                entry["related_findings"].push_back({
                    {"id", evidence.id}, {"file", evidence.file},
                    {"line_number", evidence.lineNumber}, {"hash", evidence.hash}
                });
            }
        }
        if (!detection.context.empty()) {
            entry["context"] = {
                {"start_line", detection.contextStart},
                {"lines", detection.context}
            };
        }
        logJson["detections"].push_back(std::move(entry));
    }

    if (!WriteJsonFile(OutputPath("scan_log.json"), logJson)) return Fail("Could not write scan_log.json");

    const bool isFullScan = (g_minSeverity == "low") && !g_diffMode && g_excludedTags.empty() && g_skipped.Total() == 0;
    if (isFullScan && !WriteJsonFile(OutputPath("last_scan.json"), logJson)) {
        return Fail("Could not update last_scan.json");
    }

    if (g_generateHtml) {
        HtmlReportSummary summary;
        summary.filesProcessed = g_filesProcessed.load();
        summary.decompressedArchives = g_decompressedArchives.load();
        summary.whitelisted = whitelisted;
        summary.baseline = g_filter.Count(Verdict::InBaseline);
        summary.diff = g_diffMode;
        summary.minSeverity = g_minSeverity;
        summary.scanRoot = NormalizedPath(g_scanRoot);
        if (!GenerateHtmlReport(g_reported, scores, totals, summary, g_skipped, OutputPath("scan_report.html"))) {
            return Fail("Could not write HTML report");
        }
    }

    if (g_cache && !SaveScanCache(options.cacheFile)) {
        return Fail("Could not write the cache to " + PathToUtf8(options.cacheFile));
    }

    if (g_generateSarif) {
        SarifReportSummary summary;
        summary.version = kScannerVersion;
        summary.rulesetVersion = g_rulesetVersion;
        summary.scanRoot = NormalizedPath(g_scanRoot);
        if (!WriteTextFile(OutputPath("scan_results.sarif"),
                           BuildSarifDocument(g_reported, g_patterns, summary))) {
            return Fail("Could not write scan_results.sarif");
        }
    }

    PrintFindings(g_reported, totals);

    std::ostringstream headline;
    headline << std::fixed << std::setprecision(2) << duration.count() << " s";
    headline << "  " << g_filesProcessed.load() << " files";
    if (g_decompressedArchives.load() > 0) headline << "  " << g_decompressedArchives.load() << " archives";

    std::cout << std::endl << con::Rule(60) << std::endl;
    std::cout << con::Bold("  SCAN COMPLETE") << "   " << con::Dim(headline.str()) << std::endl;
    std::cout << std::endl;

    const int widest = std::max(std::max(totals.critical, totals.high),
                                std::max(totals.medium, totals.low));
    const struct { const char* name; const char* key; int count; } rows[] = {
        { "Critical", "critical", totals.critical },
        { "High    ", "high",     totals.high },
        { "Medium  ", "medium",   totals.medium },
        { "Low     ", "low",      totals.low },
    };
    for (const auto& row : rows) {
        const int width = widest > 0 ? (row.count * 34 + widest - 1) / widest : 0;
        std::cout << "  " << con::SeverityText(row.key, row.name) << " "
                  << std::setw(5) << row.count << "  "
                  << con::Bar(row.key, row.count, width) << std::endl;
    }

    std::cout << std::endl;
    std::cout << "  " << con::Bold(std::to_string(g_detections.load()) + " findings")
              << con::Dim(" in " + std::to_string(std::min<size_t>(
                              scores.size(), static_cast<size_t>(g_filesProcessed.load())))
                          + " of " + std::to_string(g_filesProcessed.load()) + " files");
    if (g_compositeHits.load() > 0) {
        std::cout << con::Dim(", " + std::to_string(g_compositeHits.load()) + " from combination rules");
    }
    std::cout << std::endl;

    if (g_knownBadHashes.empty()) {
        std::cout << "  " << con::Dim("Known backdoors: not checked, known_hashes.txt is empty") << std::endl;
    }
    else if (!g_knownBadMatched.empty()) {
        std::cout << "  " << con::Red("Known backdoors: " + std::to_string(g_knownBadMatched.size())
                                      + " of " + std::to_string(g_knownBadHashes.size()) + " listed hashes matched") << std::endl;
    }
    else {
        std::cout << "  " << con::Green("Known backdoors: none, checked against "
                                        + std::to_string(g_knownBadHashes.size())
                                        + (g_knownBadHashes.size() == 1 ? " hash" : " hashes")) << std::endl;
    }
    if (whitelisted > 0) {
        std::cout << "  " << con::Dim(std::to_string(whitelisted) + " suppressed by whitelist.txt") << std::endl;
    }
    if (g_cache && g_cache->Hits() > 0) {
        std::cout << "  " << con::Dim(std::to_string(g_cache->Hits()) + " of "
                                      + std::to_string(g_filesProcessed.load())
                                      + " files reused from the cache, unchanged since the last run") << std::endl;
    }
    if (!g_diffMode && g_minSeverity == "low" && g_excludedTags.empty()) {
        std::vector<Whitelist::Entry> unused;
        for (const Whitelist::Entry& entry : g_whitelist.PathRules()) {
            if (entry.hits == 0) unused.push_back(entry);
        }
        if (!unused.empty()) {
            std::cout << std::endl;
            std::cout << "  " << con::Yellow(std::to_string(unused.size()) + " whitelist rule"
                      + (unused.size() == 1 ? "" : "s") + " matched nothing in this scan:") << std::endl;
            for (size_t i = 0; i < unused.size() && i < kSkipSamplesInSummary; ++i) {
                std::cout << "    " << con::Dim(unused[i].text) << std::endl;
            }
            if (unused.size() > kSkipSamplesInSummary) {
                std::cout << "    " << con::Dim("... and " + std::to_string(unused.size() - kSkipSamplesInSummary)
                          + " more") << std::endl;
            }
            std::cout << "  " << con::Dim("Either the addon is gone or the rule no longer applies.") << std::endl;
        }
    }
    if (g_diffMode) {
        std::cout << "  " << con::Dim(std::to_string(g_filter.Count(Verdict::InBaseline))
                                      + " already in the baseline") << std::endl;
    }

    const int unscanned = g_skipped.Total();
    if (unscanned > 0) {
        std::cout << std::endl;
        std::cout << "!! " << unscanned << " file" << (unscanned == 1 ? " was" : "s were")
                  << " NOT examined. This scan is incomplete." << std::endl;
        for (int i = 0; i < static_cast<int>(SkipReason::Count); ++i) {
            const SkipReason reason = static_cast<SkipReason>(i);
            const int count = g_skipped.Count(reason);
            if (count == 0) continue;

            std::cout << "   " << count << " " << SkipReasonText(reason) << ":" << std::endl;
            const std::vector<std::string> samples = g_skipped.Samples(reason, kSkipSamplesInSummary);
            for (const std::string& sample : samples) {
                std::cout << "     " << sample << std::endl;
            }
            if (count > static_cast<int>(samples.size())) {
                std::cout << "     ... and " << (count - static_cast<int>(samples.size())) << " more ("
                          << (g_skipped.Truncated()
                                  ? "scan_log.json lists the first "
                                        + std::to_string(SkipRegistry::kMaxRecordedPaths)
                                  : std::string("full list in scan_log.json"))
                          << ")" << std::endl;
            }
        }
    }

    if (!scores.empty()) {
        std::cout << std::endl << con::Bold("  Files worth reading first") << std::endl;
        for (size_t i = 0; i < std::min(scores.size(), kTopFilesInSummary); ++i) {
            const FileScore& score = scores[i];
            std::cout << "  " << con::Dim(std::to_string(i + 1) + ".") << " "
                      << RelativeToRoot(score.file) << "  "
                      << con::Dim("(" + std::to_string(score.detections) + " finding"
                                  + (score.detections == 1 ? "" : "s") + ", "
                                  + std::to_string(score.distinctTypes) + " kind"
                                  + (score.distinctTypes == 1 ? "" : "s") + ")") << std::endl;
        }
        if (scores.size() > kTopFilesInSummary) {
            std::cout << "  " << con::Dim("... and " + std::to_string(scores.size() - kTopFilesInSummary)
                                          + " more") << std::endl;
        }
    }

    std::cout << std::endl;
    std::cout << std::endl << con::Rule(60) << std::endl;
    if (g_generateHtml) {
        std::cout << "  Report: " << con::Bold(NormalizedPath(OutputPath("scan_report.html"))) << std::endl;
    }
    else {
        std::cout << "  " << con::Dim("Data:   " + NormalizedPath(OutputPath("scan_log.json"))) << std::endl;
        std::cout << "  " << con::Dim("--html also writes a browsable report.") << std::endl;
    }

    if (g_detections.load() > 0) {
        std::cout << std::endl;
        std::cout << "  " << con::Bold("Next") << std::endl;
        std::cout << "  " << con::Dim("A finding is a place to look, not a verdict. Record the ones") << std::endl;
        std::cout << "  " << con::Dim("you have read and found harmless:") << std::endl;
        std::cout << std::endl;
        std::cout << "      " << con::Blue("BD-Scan --accept <ID>@<path glob> --reason \"why\"") << std::endl;
        std::cout << std::endl;
        std::cout << "  " << con::Dim("The next scan with --diff then shows only what changed.") << std::endl;
    }
    if (!isFullScan) {
        std::cout << "Note: baseline 'last_scan.json' left unchanged (filtered or incomplete scan)." << std::endl;
    }

    PauseIfInteractive();

    if (g_detections.load() > 0) return kExitDetections;
    return unscanned > 0 ? kExitIncomplete : kExitClean;
}


}

int RunScanner(int argc, const NativeChar* argv[]) {
    try {
        return RunScanApplication(argc, argv);
    }
    catch (const std::exception& error) {
        return Fail(error.what());
    }
}
