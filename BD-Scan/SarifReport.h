#pragma once
#include <filesystem>
#include <string>
#include <vector>
#include "Report.h"

struct SarifReportSummary {
    std::string version;
    std::string rulesetVersion;
    std::string scanRoot;
};

std::string BuildSarifDocument(const std::vector<Detection>& detections, const PatternSet& patterns,
                               const SarifReportSummary& summary);
