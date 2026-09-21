#pragma once
#include <filesystem>
#include <map>
#include <string>
#include "ScanTasks.h"
#include "Rules.h"
#include "Scanner.h"

using CompositeEvidence = std::map<std::string, std::map<std::string, DetectionEvidence>>;

inline std::string CompositeScope(const std::filesystem::path& file, const std::filesystem::path& scanRoot) {
    namespace fs = std::filesystem;
    const fs::path relative = file.lexically_relative(scanRoot);
    if (relative.empty() || *relative.begin() == "..") {
        return NormalizedPath(file.parent_path());
    }

    fs::path prefix = scanRoot;
    bool namedContainer = false;
    for (const fs::path& component : relative.parent_path()) {
        const std::string name = ToLowerAscii(component.u8string());
        if (namedContainer) return NormalizedPath(prefix / component);
        if (name == "lua" || name == "materials" || name == "models" || name == "sound" || name == "resource") {
            return NormalizedPath(prefix);
        }
        prefix /= component;
        namedContainer = (name == "addons" || name == "gamemodes");
    }
    if (relative.has_parent_path()) {
        return NormalizedPath(scanRoot / *relative.begin());
    }
    return NormalizedPath(file.parent_path());
}

inline std::map<std::string, int> EvidenceCounts(const CompositeEvidence& evidence) {
    std::map<std::string, int> result;
    for (const auto& entry : evidence) result[entry.first] = static_cast<int>(entry.second.size());
    return result;
}
