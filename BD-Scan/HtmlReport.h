#pragma once
#include <filesystem>
#include "Report.h"

struct HtmlReportSummary {
    int filesProcessed = 0;
    int decompressedArchives = 0;
    int whitelisted = 0;
    int baseline = 0;
    bool diff = false;
    std::string minSeverity = "low";
    std::string scanRoot;
};

bool GenerateHtmlReport(const std::vector<Detection>& detections, const std::vector<FileScore>& scores,
                        const SeverityTotals& totals, const HtmlReportSummary& summary,
                        const SkipRegistry& skipped, const std::filesystem::path& path);
