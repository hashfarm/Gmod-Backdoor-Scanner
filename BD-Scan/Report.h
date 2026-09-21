#pragma once
#include <string>
#include <vector>
#include <set>
#include <map>
#include <mutex>
#include <algorithm>

#include "Rules.h"
#include "Scanner.h"

inline int SeverityRank(const std::string& severity) {
    if (severity == "critical") return 0;
    if (severity == "high") return 1;
    if (severity == "medium") return 2;
    return 3;
}

inline int SeverityWeight(const std::string& severity) {
    if (severity == "critical") return 10;
    if (severity == "high") return 3;
    if (severity == "medium") return 1;
    return 0;
}

inline bool IsValidSeverity(const std::string& severity) {
    return severity == "low" || severity == "medium" || severity == "high" || severity == "critical";
}

inline bool MeetsSeverityThreshold(const std::string& severity, const std::string& minimum) {
    return SeverityRank(severity) <= SeverityRank(minimum);
}

enum class Verdict {
    Report = 0,
    BelowSeverity,
    Whitelisted,
    Duplicate,
    InBaseline,
    Count
};

class ReportFilter {
public:
    void SetMinSeverity(const std::string& severity) { m_minSeverity = severity; }
    void SetWhitelist(const Whitelist* whitelist) { m_whitelist = whitelist; }

    void SetBaseline(std::set<std::string> keys) {
        m_baseline = std::move(keys);
        m_diffMode = true;
    }

    bool DiffMode() const { return m_diffMode; }
    size_t BaselineSize() const { return m_baseline.size(); }

    static std::string Key(const Detection& detection) {
        const std::string& identity = detection.id.empty() ? detection.detection : detection.id;
        return detection.file + ":" + std::to_string(detection.lineNumber) + ":" + identity + ":" + detection.fingerprint;
    }

    Verdict Evaluate(const Detection& detection) {
        std::lock_guard<std::mutex> lock(m_mutex);
        const Verdict verdict = Decide(detection);
        m_counts[static_cast<size_t>(verdict)]++;
        return verdict;
    }

    int Count(Verdict verdict) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_counts[static_cast<size_t>(verdict)];
    }

private:
    Verdict Decide(const Detection& detection) {
        if (!MeetsSeverityThreshold(detection.severity, m_minSeverity)) return Verdict::BelowSeverity;
        const std::string& whitelistPath =
            detection.container.empty() ? detection.file : detection.container;
        if (m_whitelist != nullptr && m_whitelist->IsSuppressed(whitelistPath, detection.detection)) {
            return Verdict::Whitelisted;
        }

        const std::string key = Key(detection);
        if (!m_seen.insert(key).second) return Verdict::Duplicate;
        if (m_diffMode && m_baseline.find(key) != m_baseline.end()) return Verdict::InBaseline;
        return Verdict::Report;
    }

    std::string m_minSeverity = "low";
    const Whitelist* m_whitelist = nullptr;
    std::set<std::string> m_baseline;
    bool m_diffMode = false;
    std::set<std::string> m_seen;
    int m_counts[static_cast<size_t>(Verdict::Count)] = {};
    mutable std::mutex m_mutex;
};

enum class SkipReason {
    TooLarge = 0,
    Compressed,
    Unreadable,
    Malformed,
    PatternLimit,
    StringLimit,
    ScanError,
    Count
};

inline const char* SkipReasonName(SkipReason reason) {
    switch (reason) {
        case SkipReason::TooLarge:   return "too_large";
        case SkipReason::Compressed: return "compressed_archive";
        case SkipReason::Unreadable: return "unreadable";
        case SkipReason::Malformed:  return "malformed_archive";
        case SkipReason::PatternLimit: return "pattern_limit";
        case SkipReason::StringLimit: return "string_limit";
        case SkipReason::ScanError: return "scan_error";
        default:                     return "unknown";
    }
}

inline const char* SkipReasonText(SkipReason reason) {
    switch (reason) {
        case SkipReason::TooLarge:   return "larger than the size limit";
        case SkipReason::Compressed: return "compressed archive (extract with gmad first)";
        case SkipReason::Unreadable: return "could not be opened or read";
        case SkipReason::Malformed:  return "malformed archive";
        case SkipReason::PatternLimit: return "only partly examined (a pattern hit the regex complexity limit)";
        case SkipReason::StringLimit: return "only partly examined (more text inside it than the string limit)";
        case SkipReason::ScanError: return "scan failed while processing the file";
        default:                     return "unknown reason";
    }
}

class SkipRegistry {
public:
    static constexpr size_t kMaxRecordedPaths = 2000;

    void Add(SkipReason reason, const std::string& path, const std::string& detail = "") {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_counts[static_cast<size_t>(reason)]++;
        if (m_entries.size() < kMaxRecordedPaths) {
            m_entries.push_back({ reason, path, detail });
        }
    }

    int Count(SkipReason reason) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_counts[static_cast<size_t>(reason)];
    }

    int Total() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        int total = 0;
        for (int count : m_counts) total += count;
        return total;
    }

    bool Truncated() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_entries.size() >= kMaxRecordedPaths;
    }

    struct Entry {
        SkipReason reason;
        std::string path;
        std::string detail;
    };

    std::vector<Entry> Entries() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<Entry> sorted = m_entries;
        std::sort(sorted.begin(), sorted.end(), [](const Entry& a, const Entry& b) {
            if (a.reason != b.reason) return a.reason < b.reason;
            return a.path < b.path;
        });
        return sorted;
    }

    std::vector<std::string> Samples(SkipReason reason, size_t limit) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<std::string> result;
        for (const Entry& entry : m_entries) {
            if (entry.reason == reason) result.push_back(entry.path);
        }
        std::sort(result.begin(), result.end());
        if (result.size() > limit) result.resize(limit);
        return result;
    }

private:
    int m_counts[static_cast<size_t>(SkipReason::Count)] = {};
    std::vector<Entry> m_entries;
    mutable std::mutex m_mutex;
};

struct FileScore {
    std::string file;
    int score = 0;
    int detections = 0;
    int distinctTypes = 0;
    int critical = 0;
    int high = 0;
    int medium = 0;
    int low = 0;
};

inline std::vector<FileScore> ComputeFileScores(const std::vector<Detection>& detections) {
    std::map<std::string, FileScore> byFile;
    std::map<std::string, std::set<std::string>> typesByFile;

    for (const Detection& detection : detections) {
        FileScore& score = byFile[detection.file];
        score.file = detection.file;
        score.detections++;

        if (detection.severity == "critical") score.critical++;
        else if (detection.severity == "high") score.high++;
        else if (detection.severity == "medium") score.medium++;
        else score.low++;

        if (typesByFile[detection.file].insert(detection.detection).second) {
            score.score += SeverityWeight(detection.severity);
            score.distinctTypes++;
        }
    }

    std::vector<FileScore> result;
    result.reserve(byFile.size());
    for (auto& entry : byFile) result.push_back(std::move(entry.second));

    std::sort(result.begin(), result.end(), [](const FileScore& a, const FileScore& b) {
        if (a.score != b.score) return a.score > b.score;
        if (a.critical != b.critical) return a.critical > b.critical;
        return a.file < b.file;
    });
    return result;
}

inline bool DetectionOrder(const Detection& a, const Detection& b) {
    if (a.file != b.file) return a.file < b.file;
    if (a.lineNumber != b.lineNumber) return a.lineNumber < b.lineNumber;
    return a.detection < b.detection;
}

struct SeverityTotals {
    int critical = 0;
    int high = 0;
    int medium = 0;
    int low = 0;
};

inline SeverityTotals TotalsOf(const std::vector<Detection>& detections) {
    SeverityTotals totals;
    for (const Detection& detection : detections) {
        if (detection.severity == "critical") totals.critical++;
        else if (detection.severity == "high") totals.high++;
        else if (detection.severity == "medium") totals.medium++;
        else totals.low++;
    }
    return totals;
}

