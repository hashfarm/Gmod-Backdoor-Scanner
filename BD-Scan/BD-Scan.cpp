#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <regex>
#include <vector>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <future>
#include <algorithm>
#include <mutex>
#include <atomic>
#include <set>
#include <nlohmann/json.hpp>

#include "CheckDefs.h"
#include "CleanString.h"
#include "GMAReader.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

// Thread-safe mutex for logging
std::mutex g_logMutex;
std::mutex g_jsonMutex;
std::atomic<int> g_filesProcessed{0};
std::atomic<int> g_detections{0};
std::atomic<int> g_criticalCount{0};
std::atomic<int> g_highCount{0};
std::atomic<int> g_mediumCount{0};
std::atomic<int> g_lowCount{0};

// CLI options
std::string g_minSeverity = "low";
bool g_quietMode = false;
bool g_generateHtml = false;
bool g_diffMode = false;
std::string g_lastScanFile = "last_scan.json";

// Known malicious file hashes (MD5-style simple hash)
std::set<std::string> g_knownBadHashes;
std::set<std::string> g_lastScanDetections;
std::atomic<int> g_knownBadFound{0};
std::atomic<int> g_newDetections{0};

// Definition of global vectors
std::vector<std::string> LuaCheckPatterns, LuaCheckDefs;
std::vector<std::regex> LuaCheckRegex;
std::vector<std::string> VMTRegexPatterns, VMTRegexDefs;
std::vector<std::regex> VMTRegexPatternsRegex;
std::vector<std::string> VTFRegexPatterns, VTFRegexDefs;
std::vector<std::regex> VTFRegexPatternsRegex;
std::vector<std::string> TTFRegexPatterns, TTFRegexDefs;
std::vector<std::regex> TTFRegexPatternsRegex;

// Forward declarations
void LogConsole(const std::string& message);

// Base64 decoding table
static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool isBase64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string DecodeBase64(const std::string& encoded) {
    std::string decoded;
    int in_len = static_cast<int>(encoded.size());
    int i = 0, j = 0, in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];

    while (in_len-- && (encoded[in_] != '=') && isBase64(encoded[in_])) {
        char_array_4[i++] = encoded[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = static_cast<unsigned char>(base64_chars.find(char_array_4[i]));
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (i = 0; i < 3; i++)
                decoded += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;
        for (j = 0; j < 4; j++)
            char_array_4[j] = static_cast<unsigned char>(base64_chars.find(char_array_4[j]));
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
        for (j = 0; j < (i - 1); j++)
            decoded += char_array_3[j];
    }

    return decoded;
}

// Simple hash function for file content (DJB2)
std::string ComputeFileHash(const std::string& content) {
    unsigned long hash = 5381;
    for (char c : content) {
        hash = ((hash << 5) + hash) + static_cast<unsigned char>(c);
    }
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << hash;
    return ss.str();
}

// Load known bad hashes from file
void LoadKnownBadHashes(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return;
    
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line[0] != '#') {
            // Format: hash;;;description
            size_t pos = line.find(";;;");
            if (pos != std::string::npos) {
                g_knownBadHashes.insert(line.substr(0, pos));
            } else {
                g_knownBadHashes.insert(line);
            }
        }
    }
    file.close();
}

// Load last scan results for diff mode
void LoadLastScanResults() {
    std::ifstream file(g_lastScanFile);
    if (!file.is_open()) return;
    
    try {
        json lastScan;
        file >> lastScan;
        file.close();
        
        if (lastScan.contains("detections")) {
            for (const auto& det : lastScan["detections"]) {
                // Create unique key: file + line + detection
                std::string key = det.value("file", "") + ":" + 
                                  std::to_string(det.value("line_number", 0)) + ":" +
                                  det.value("detection", "");
                g_lastScanDetections.insert(key);
            }
        }
    } catch (...) {
        // Ignore parse errors
    }
}

// Check if detection is new (for diff mode)
bool IsNewDetection(const std::string& filePath, int lineNum, const std::string& detection) {
    std::string key = filePath + ":" + std::to_string(lineNum) + ":" + detection;
    return g_lastScanDetections.find(key) == g_lastScanDetections.end();
}

// Check file against known bad hashes
bool CheckKnownBadHash(const std::string& filePath, const std::string& content, json& logJson) {
    if (g_knownBadHashes.empty()) return false;
    
    std::string hash = ComputeFileHash(content);
    if (g_knownBadHashes.find(hash) != g_knownBadHashes.end()) {
        g_knownBadFound++;
        LogConsole("[KNOWN BACKDOOR] " + filePath + " (Hash: " + hash + ")\n");
        
        std::lock_guard<std::mutex> lock(g_jsonMutex);
        json entry;
        entry["file"] = filePath;
        entry["severity"] = "critical";
        entry["detection"] = "[CRITICAL] Known Backdoor (Hash Match)";
        entry["line_number"] = 0;
        entry["line_text"] = "File hash: " + hash;
        entry["hash"] = hash;
        logJson["detections"].push_back(entry);
        g_criticalCount++;
        return true;
    }
    return false;
}

// Console logging (thread-safe)
void LogConsole(const std::string& message) {
    if (g_quietMode) return;
    std::lock_guard<std::mutex> lock(g_logMutex);
    std::cout << message;
}

// Get severity level from detection string
std::string GetSeverity(const std::string& detection) {
    if (detection.find("[CRITICAL]") != std::string::npos) return "critical";
    if (detection.find("[HIGH]") != std::string::npos) return "high";
    if (detection.find("[MEDIUM]") != std::string::npos) return "medium";
    return "low";
}

// Check if severity meets minimum threshold
bool MeetsSeverityThreshold(const std::string& severity) {
    if (g_minSeverity == "low") return true;
    if (g_minSeverity == "medium") return severity != "low";
    if (g_minSeverity == "high") return severity == "high" || severity == "critical";
    if (g_minSeverity == "critical") return severity == "critical";
    return true;
}

// Update severity counters
void UpdateSeverityCount(const std::string& severity) {
    if (severity == "critical") g_criticalCount++;
    else if (severity == "high") g_highCount++;
    else if (severity == "medium") g_mediumCount++;
    else g_lowCount++;
}

// JSON logging (thread-safe)
void LogJson(json& logJson, const std::string& filePath, const std::string& detection, int lineNum, const std::string& lineText, const std::string& decodedContent = "") {
    std::string severity = GetSeverity(detection);

    // Skip if below minimum severity
    if (!MeetsSeverityThreshold(severity)) return;

    UpdateSeverityCount(severity);

    std::lock_guard<std::mutex> lock(g_jsonMutex);
    json entry;
    entry["file"] = filePath;
    entry["severity"] = severity;
    entry["detection"] = detection;
    entry["line_number"] = lineNum;
    entry["line_text"] = lineText;
    if (!decodedContent.empty()) {
        entry["decoded_content"] = decodedContent;
    }
    logJson["detections"].push_back(entry);
}

// Decode and log char codes
std::string DecodeCharCode(const std::string& LineSubject, const std::regex& CheckRegex) {
    std::stringstream ss;
    std::smatch Match;
    std::string remaining = LineSubject;
    try {
        while (std::regex_search(remaining, Match, CheckRegex)) {
            int value = std::stoi(Match.str(0));
            if (value >= 0 && value <= 255) {
                ss << static_cast<char>(value);
            }
            remaining = Match.suffix().str();
        }
    }
    catch (const std::exception&) {
        // Ignore decode errors
    }
    return ss.str();
}

// Check a single line for patterns - returns number of detections
int CheckLine(const std::string& Line, int LineNum, const std::string& FilePath, const std::string& FileType, json& logJson) {
    int detectionCount = 0;

    auto performCheck = [&](const std::vector<std::regex>& regexes, const std::vector<std::string>& defs, const std::string& fileTypeLabel) {
        for (size_t i = 0; i < regexes.size(); ++i) {
            if (std::regex_search(Line, regexes[i])) {
                detectionCount++;
                std::stringstream ss;
                ss << FilePath << " | " << defs[i] << " in a " << fileTypeLabel << " @ Line #" << LineNum << " | " << trimExtraWhiteSpaces(Line);

                std::string decodedContent;
                if (defs[i].find("CharCode") != std::string::npos || defs[i].find("Obfuscation") != std::string::npos) {
                    decodedContent = DecodeCharCode(Line, regexes[i]);
                    if (!decodedContent.empty()) {
                        ss << " -> Decoded: " << decodedContent;
                    }
                }
                else if (defs[i].find("Base64") != std::string::npos) {
                    // Try to decode Base64
                    static std::regex base64Extract(R"([A-Za-z0-9+/]{40,}={0,2})");
                    std::smatch match;
                    if (std::regex_search(Line, match, base64Extract)) {
                        decodedContent = DecodeBase64(match.str());
                        // Only show if decoded content looks like text
                        bool isPrintable = true;
                        for (size_t c = 0; c < std::min(decodedContent.length(), (size_t)50); c++) {
                            if (decodedContent[c] < 32 && decodedContent[c] != '\n' && decodedContent[c] != '\r' && decodedContent[c] != '\t') {
                                isPrintable = false;
                                break;
                            }
                        }
                        if (isPrintable && !decodedContent.empty() && decodedContent.length() > 5) {
                            ss << " -> Decoded: " << decodedContent.substr(0, 100);
                            if (decodedContent.length() > 100) ss << "...";
                        } else {
                            decodedContent = ""; // Don't store binary data
                        }
                    }
                }

                LogConsole(ss.str() + "\n");
                LogJson(logJson, FilePath, defs[i], LineNum, trimExtraWhiteSpaces(Line), decodedContent);
            }
        }
    };

    // Check patterns based on file type
    if (FileType == ".lua") {
        performCheck(LuaCheckRegex, LuaCheckDefs, "LUA");
    }
    else if (FileType == ".vmt") {
        performCheck(VMTRegexPatternsRegex, VMTRegexDefs, "VMT");
    }
    else if (FileType == ".vtf") {
        performCheck(VTFRegexPatternsRegex, VTFRegexDefs, "VTF");
    }
    else if (FileType == ".ttf") {
        performCheck(TTFRegexPatternsRegex, TTFRegexDefs, "TTF");
    }

    return detectionCount;
}

// Process a single file
void ProcessFile(const fs::path& filePath, json& logJson) {
    try {
        if (fs::file_size(filePath) == 0) return;
    } catch (const fs::filesystem_error&) {
        return;
    }

    std::ifstream inFile(filePath);
    if (!inFile.is_open()) {
        LogConsole("Error: Could not open file: " + filePath.string() + "\n");
        return;
    }

    // Read entire file for hash check
    std::stringstream buffer;
    buffer << inFile.rdbuf();
    std::string fileContent = buffer.str();
    inFile.close();

    std::string NormalPath = filePath.string();
    std::replace(NormalPath.begin(), NormalPath.end(), '\\', '/');
    std::string extension = filePath.extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

    // Check against known bad hashes
    if (CheckKnownBadHash(NormalPath, fileContent, logJson)) {
        g_detections++;
        g_filesProcessed++;
        return; // Skip pattern matching for known bad files
    }

    // Process line by line for pattern matching
    std::istringstream stream(fileContent);
    std::string FileText;
    int LineNum = 0;

    while (std::getline(stream, FileText)) {
        LineNum++;
        int lineDetections = CheckLine(FileText, LineNum, NormalPath, extension, logJson);
        g_detections += lineDetections;
    }
    g_filesProcessed++;
}

// Process a GMA file (Garry's Mod Addon)
void ProcessGMAFile(const fs::path& gmaPath, json& logJson) {
    GMAInfo info = GMAReader::ReadGMAInfo(gmaPath);
    if (!info.valid) {
        LogConsole("Error: Could not read GMA file: " + gmaPath.string() + "\n");
        return;
    }

    int64_t contentOffset = GMAReader::GetContentStartOffset(gmaPath);
    if (contentOffset < 0) {
        LogConsole("Error: Could not determine content offset in GMA: " + gmaPath.string() + "\n");
        return;
    }

    std::string gmaBasePath = gmaPath.string();
    std::replace(gmaBasePath.begin(), gmaBasePath.end(), '\\', '/');

    LogConsole("Scanning GMA: " + info.name + " (" + std::to_string(info.files.size()) + " files)\n");

    for (const auto& entry : info.files) {
        if (!GMAReader::IsScannableFile(entry.filename)) continue;

        std::string content = GMAReader::ExtractFileContent(gmaPath, entry, contentOffset);
        if (content.empty()) continue;

        std::string virtualPath = gmaBasePath + "/" + entry.filename;
        std::string extension = GMAReader::GetExtension(entry.filename);

        // Process content line by line
        std::istringstream stream(content);
        std::string line;
        int lineNum = 0;

        while (std::getline(stream, line)) {
            lineNum++;
            int lineDetections = CheckLine(line, lineNum, virtualPath, extension, logJson);
            g_detections += lineDetections;
        }
        g_filesProcessed++;
    }
}

void PrintUsage() {
    std::cout << "Usage: BD-Scan.exe [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -d <directory>    Directory to scan" << std::endl;
    std::cout << "  -s <severity>     Minimum severity level (low/medium/high/critical)" << std::endl;
    std::cout << "  -q, --quiet       Quiet mode (only show summary)" << std::endl;
    std::cout << "  --html            Generate HTML report" << std::endl;
    std::cout << "  --diff            Show only NEW detections since last scan" << std::endl;
    std::cout << "  -h, --help        Show this help message" << std::endl;
    std::cout << std::endl;
    std::cout << "Files:" << std::endl;
    std::cout << "  known_hashes.txt  Known backdoor hashes (auto-loaded)" << std::endl;
    std::cout << "  last_scan.json    Previous scan results (for --diff)" << std::endl;
}

void GenerateHtmlReport(const json& logJson, const std::string& filename) {
    std::ofstream html(filename);
    if (!html.is_open()) return;

    html << R"(
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Gmod Backdoor Scan Report</title>
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }
h1 { color: #00d4ff; }
.stats { display: flex; gap: 20px; margin: 20px 0; }
.stat-box { padding: 15px 25px; border-radius: 8px; text-align: center; }
.critical { background: #dc3545; }
.high { background: #fd7e14; }
.medium { background: #ffc107; color: #000; }
.low { background: #28a745; }
.detection { background: #16213e; margin: 10px 0; padding: 15px; border-radius: 8px; border-left: 4px solid; }
.detection.critical { border-color: #dc3545; }
.detection.high { border-color: #fd7e14; }
.detection.medium { border-color: #ffc107; }
.detection.low { border-color: #28a745; }
.file { color: #00d4ff; font-size: 0.9em; }
.line { color: #888; }
code { background: #0f0f23; padding: 8px; display: block; margin-top: 8px; border-radius: 4px; overflow-x: auto; }
.severity-tag { padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
</style></head><body>
<h1>Gmod Backdoor Scan Report</h1>
)";

    html << "<div class='stats'>";
    html << "<div class='stat-box critical'><strong>" << g_criticalCount.load() << "</strong><br>Critical</div>";
    html << "<div class='stat-box high'><strong>" << g_highCount.load() << "</strong><br>High</div>";
    html << "<div class='stat-box medium'><strong>" << g_mediumCount.load() << "</strong><br>Medium</div>";
    html << "<div class='stat-box low'><strong>" << g_lowCount.load() << "</strong><br>Low</div>";
    html << "</div>";

    html << "<p>Files scanned: " << g_filesProcessed.load() << "</p>";

    if (logJson.contains("detections")) {
        for (const auto& det : logJson["detections"]) {
            std::string sev = det.value("severity", "low");
            html << "<div class='detection " << sev << "'>";
            html << "<span class='severity-tag " << sev << "'>" << sev << "</span> ";
            html << "<strong>" << det.value("detection", "") << "</strong><br>";
            html << "<span class='file'>" << det.value("file", "") << "</span> ";
            html << "<span class='line'>Line " << det.value("line_number", 0) << "</span>";
            html << "<code>" << det.value("line_text", "") << "</code>";
            if (det.contains("decoded_content") && !det["decoded_content"].get<std::string>().empty()) {
                html << "<code style='color:#00ff88'>Decoded: " << det["decoded_content"].get<std::string>() << "</code>";
            }
            html << "</div>";
        }
    }

    html << "</body></html>";
    html.close();
}

int main(int argc, char* argv[]) {
    std::cout << R"(
  ============================================================
  ||                                                        ||
  ||   GMod Backdoor Scanner v2.0                           ||
  ||   Detect malicious code in Garry's Mod files           ||
  ||                                                        ||
  ============================================================
)" << std::endl;

    // Load patterns
    if (!LoadAllPatterns()) {
        std::cerr << "Critical error: Patterns could not be loaded. Please ensure the .txt files are present." << std::endl;
        std::cout << "Press Enter to continue...";
        std::cin.get();
        return 1;
    }
    std::cout << "Patterns loaded successfully." << std::endl;

    // Parse command line arguments
    std::wstring InputDirectory;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            PrintUsage();
            return 0;
        }
        else if (arg == "-d" && i + 1 < argc) {
            InputDirectory = std::wstring(argv[i + 1], argv[i + 1] + strlen(argv[i + 1]));
            i++;
        }
        else if (arg == "-s" && i + 1 < argc) {
            g_minSeverity = argv[i + 1];
            i++;
        }
        else if (arg == "-q" || arg == "--quiet") {
            g_quietMode = true;
        }
        else if (arg == "--html") {
            g_generateHtml = true;
        }
        else if (arg == "--diff") {
            g_diffMode = true;
        }
    }

    // Load known bad hashes
    LoadKnownBadHashes("known_hashes.txt");
    if (!g_knownBadHashes.empty()) {
        std::cout << "Loaded " << g_knownBadHashes.size() << " known bad hashes." << std::endl;
    }

    // Load last scan for diff mode
    if (g_diffMode) {
        LoadLastScanResults();
        if (!g_lastScanDetections.empty()) {
            std::cout << "Diff mode: Comparing against " << g_lastScanDetections.size() << " previous detections." << std::endl;
        } else {
            std::cout << "Diff mode: No previous scan found, showing all detections." << std::endl;
        }
    }

    if (InputDirectory.empty()) {
        std::cout << std::endl;
        std::cout << "Available options:" << std::endl;
        std::cout << "  --html        Generate HTML report" << std::endl;
        std::cout << "  --diff        Show only NEW detections" << std::endl;
        std::cout << "  -q            Quiet mode" << std::endl;
        std::cout << "  -s <level>    Severity filter (low/medium/high/critical)" << std::endl;
        std::cout << std::endl;
        std::wcout << L"Enter path [options]: ";
        std::wstring inputLine;
        std::getline(std::wcin, inputLine);
        
        // Parse the input line for path and options
        std::wstringstream wss(inputLine);
        std::wstring token;
        bool firstToken = true;
        
        while (wss >> token) {
            // Convert to narrow string for option checking
            std::string narrowToken;
            for (wchar_t wc : token) {
                narrowToken += static_cast<char>(wc);
            }
            
            if (firstToken) {
                // First token is the directory (might have quotes)
                InputDirectory = token;
                firstToken = false;
            }
            else if (narrowToken == "--html") {
                g_generateHtml = true;
            }
            else if (narrowToken == "--diff") {
                g_diffMode = true;
            }
            else if (narrowToken == "-q" || narrowToken == "--quiet") {
                g_quietMode = true;
            }
            else if (narrowToken == "-s" && wss >> token) {
                g_minSeverity.clear();
                for (wchar_t wc : token) {
                    g_minSeverity += static_cast<char>(wc);
                }
            }
            else if (narrowToken.find("--") == std::string::npos && narrowToken.find("-") != 0) {
                // Might be part of a path with spaces, append to directory
                InputDirectory += L" " + token;
            }
        }
        
        // Load diff mode data if enabled via interactive input
        if (g_diffMode && g_lastScanDetections.empty()) {
            LoadLastScanResults();
            if (!g_lastScanDetections.empty()) {
                std::cout << "Diff mode: Comparing against " << g_lastScanDetections.size() << " previous detections." << std::endl;
            } else {
                std::cout << "Diff mode: No previous scan found, showing all detections." << std::endl;
            }
        }
    }

    // Remove quotation marks if present
    if (!InputDirectory.empty() && InputDirectory.front() == L'"') {
        size_t endQuote = InputDirectory.find(L'"', 1);
        if (endQuote != std::wstring::npos) {
            InputDirectory = InputDirectory.substr(1, endQuote - 1);
        } else if (InputDirectory.back() == L'"') {
            InputDirectory = InputDirectory.substr(1, InputDirectory.length() - 2);
        }
    }

    // Validate directory
    try {
        fs::path dir(InputDirectory);
        if (!fs::exists(dir) || !fs::is_directory(dir)) {
            std::wcerr << L"Error: Invalid or inaccessible directory." << std::endl;
            std::cout << "Press Enter to continue...";
            std::cin.get();
            return 1;
        }
        std::wcout << L"Selected directory: " << InputDirectory << std::endl << std::endl;
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "Error: Filesystem error: " << e.what() << std::endl;
        std::cout << "Press Enter to continue...";
        std::cin.get();
        return 1;
    }

    // Open log file
    std::ofstream logFile("scan_log.json");
    if (!logFile.is_open()) {
        std::cerr << "Error: Could not create log file." << std::endl;
        std::cout << "Press Enter to continue...";
        std::cin.get();
        return 1;
    }

    // Initialize JSON object explicitly
    json logJson = json::object();
    logJson["detections"] = json::array();
    logJson["start_time"] = std::chrono::system_clock::now().time_since_epoch().count();

    // Reset atomic counters
    g_filesProcessed = 0;
    g_detections = 0;

    // Scan files
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<std::future<void>> futures;
    std::string CheckFileTypes[] = { ".lua", ".vmt", ".vtf", ".ttf", ".gma" };

    for (const auto& entry : fs::recursive_directory_iterator(InputDirectory)) {
        if (entry.is_regular_file() && entry.path().has_extension()) {
            std::string extension = entry.path().extension().string();
            std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
            if (std::find(std::begin(CheckFileTypes), std::end(CheckFileTypes), extension) != std::end(CheckFileTypes)) {
                if (extension == ".gma") {
                    futures.push_back(std::async(std::launch::async, ProcessGMAFile, entry.path(), std::ref(logJson)));
                } else {
                    futures.push_back(std::async(std::launch::async, ProcessFile, entry.path(), std::ref(logJson)));
                }
            }
        }
    }

    for (auto& future : futures) {
        future.wait();
    }

    // Finalize logging
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;

    logJson["end_time"] = std::chrono::system_clock::now().time_since_epoch().count();
    logJson["files_processed"] = g_filesProcessed.load();
    logJson["detections_found"] = g_detections.load();
    logJson["statistics"] = {
        {"critical", g_criticalCount.load()},
        {"high", g_highCount.load()},
        {"medium", g_mediumCount.load()},
        {"low", g_lowCount.load()}
    };
    logFile << logJson.dump(4) << std::endl;
    logFile.close();

    // Save as last_scan.json for future diff comparisons
    std::ofstream lastScanFile("last_scan.json");
    if (lastScanFile.is_open()) {
        lastScanFile << logJson.dump(4) << std::endl;
        lastScanFile.close();
    }

    if (g_generateHtml) {
        GenerateHtmlReport(logJson, "scan_report.html");
        std::cout << "HTML report saved to 'scan_report.html'" << std::endl;
    }

    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "           SCAN COMPLETE" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Duration:        " << std::fixed << std::setprecision(2) << duration.count() << " seconds" << std::endl;
    std::cout << "Files scanned:   " << g_filesProcessed.load() << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    std::cout << "  CRITICAL:  " << g_criticalCount.load() << std::endl;
    std::cout << "  HIGH:      " << g_highCount.load() << std::endl;
    std::cout << "  MEDIUM:    " << g_mediumCount.load() << std::endl;
    std::cout << "  LOW:       " << g_lowCount.load() << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    std::cout << "  TOTAL:     " << g_detections.load() << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "Results saved to 'scan_log.json'" << std::endl;
    std::cout << "Press Enter to exit...";
    std::cin.get();

    return 0;
}