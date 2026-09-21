#include "SarifReport.h"

#include <map>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace {

std::string LevelFor(const std::string& severity) {
    if (severity == "critical" || severity == "high") return "error";
    if (severity == "medium") return "warning";
    return "note";
}

std::string SecuritySeverityFor(const std::string& severity) {
    if (severity == "critical") return "9.3";
    if (severity == "high") return "7.5";
    if (severity == "medium") return "5.0";
    return "2.0";
}

std::string TitleOf(const std::string& definition, const std::string& id) {
    const size_t close = definition.find(']');
    std::string text = close == std::string::npos ? definition : definition.substr(close + 1);
    while (!text.empty() && text.front() == ' ') text.erase(text.begin());
    if (!id.empty() && text.rfind(id, 0) == 0) {
        text.erase(0, id.size());
        while (!text.empty() && text.front() == ' ') text.erase(text.begin());
    }
    return text.empty() ? definition : text;
}

std::string RelativeUri(const std::string& file, const std::string& root) {
    if (root.empty() || file.size() <= root.size()) return file;
    if (file.compare(0, root.size(), root) != 0) return file;
    size_t start = root.size();
    while (start < file.size() && (file[start] == '/' || file[start] == '\\')) start++;
    return file.substr(start);
}

std::string PercentEncode(const std::string& text) {
    static const std::string unreserved =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@/";
    static const char digits[] = "0123456789ABCDEF";

    std::string encoded;
    encoded.reserve(text.size());
    for (unsigned char c : text) {
        if (unreserved.find(static_cast<char>(c)) != std::string::npos) {
            encoded += static_cast<char>(c);
            continue;
        }
        encoded += '%';
        encoded += digits[c >> 4];
        encoded += digits[c & 0x0F];
    }
    return encoded;
}

}

std::string BuildSarifDocument(const std::vector<Detection>& detections, const PatternSet& patterns,
                               const SarifReportSummary& summary) {
    json rules = json::array();
    json results = json::array();
    std::map<std::string, size_t> ruleIndex;

    for (const Detection& detection : detections) {
        const std::string id = detection.id.empty() ? std::string("BD-SCAN") : detection.id;

        if (ruleIndex.find(id) == ruleIndex.end()) {
            const Pattern* pattern = patterns.ById(id);
            const std::string definition = pattern != nullptr ? pattern->definition : detection.detection;
            const std::string hint = pattern != nullptr ? pattern->hint : detection.hint;

            json rule;
            rule["id"] = id;
            rule["name"] = TitleOf(definition, id);
            rule["shortDescription"]["text"] = TitleOf(definition, id);
            if (!hint.empty()) rule["fullDescription"]["text"] = hint;
            rule["defaultConfiguration"]["level"] = LevelFor(detection.severity);
            rule["properties"]["security-severity"] = SecuritySeverityFor(detection.severity);

            json tags = json::array();
            tags.push_back("security");
            if (pattern != nullptr) {
                for (const std::string& tag : pattern->tags) tags.push_back(tag);
                if (!pattern->reference.empty()) rule["helpUri"] = pattern->reference;
            }
            rule["properties"]["tags"] = tags;

            ruleIndex[id] = rules.size();
            rules.push_back(rule);
        }

        const std::string& located = detection.container.empty() ? detection.file : detection.container;

        json result;
        result["ruleId"] = id;
        result["ruleIndex"] = ruleIndex[id];
        result["level"] = LevelFor(detection.severity);

        std::string message = TitleOf(detection.detection, id);
        if (!detection.container.empty()) {
            message += " (archive entry " + RelativeUri(detection.file, detection.container) + ")";
        }
        if (!detection.hint.empty()) message += "\n\n" + detection.hint;
        result["message"]["text"] = message;

        json location;
        location["physicalLocation"]["artifactLocation"]["uri"] =
            PercentEncode(RelativeUri(located, summary.scanRoot));
        if (detection.lineNumber > 0 && detection.container.empty()) {
            location["physicalLocation"]["region"]["startLine"] = detection.lineNumber;
            if (!detection.lineText.empty()) {
                location["physicalLocation"]["region"]["snippet"]["text"] = detection.lineText;
            }
        }
        result["locations"] = json::array({ location });

        if (!detection.fingerprint.empty()) {
            result["partialFingerprints"]["bdScanFingerprint/v1"] = detection.fingerprint;
        }

        results.push_back(result);
    }

    json driver;
    driver["name"] = "BD-Scan";
    driver["version"] = summary.version;
    driver["informationUri"] = "https://github.com/RRelicc/Gmod-Backdoor-Scanner";
    driver["semanticVersion"] = summary.version;
    driver["rules"] = rules;
    if (!summary.rulesetVersion.empty()) {
        driver["properties"]["rulesetVersion"] = summary.rulesetVersion;
    }

    json run;
    run["tool"]["driver"] = driver;
    run["results"] = results;
    run["columnKind"] = "utf16CodeUnits";

    json document;
    document["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json";
    document["version"] = "2.1.0";
    document["runs"] = json::array({ run });

    return document.dump(2) + "\n";
}
