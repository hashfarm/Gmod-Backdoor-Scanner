#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <regex>

extern std::vector<std::string> LuaCheckPatterns, LuaCheckDefs;
extern std::vector<std::regex> LuaCheckRegex;
extern std::vector<std::string> VMTRegexPatterns, VMTRegexDefs;
extern std::vector<std::regex> VMTRegexPatternsRegex;
extern std::vector<std::string> VTFRegexPatterns, VTFRegexDefs;
extern std::vector<std::regex> VTFRegexPatternsRegex;
extern std::vector<std::string> TTFRegexPatterns, TTFRegexDefs;
extern std::vector<std::regex> TTFRegexPatternsRegex;

inline bool LoadPatternsFromFile(const std::string& filename, std::vector<std::string>& patterns, std::vector<std::string>& defs, std::vector<std::regex>& regexes) {
    std::ifstream configFile(filename);
    if (!configFile.is_open()) {
        std::cerr << "Error: Could not open configuration file: " << filename << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(configFile, line)) {
        if (line.empty() || line.find(";;;") == std::string::npos) {
            std::cerr << "Warning: Invalid line in " << filename << ": " << line << std::endl;
            continue;
        }
        size_t separatorPos = line.find(";;;");
        patterns.push_back(line.substr(0, separatorPos));
        defs.push_back(line.substr(separatorPos + 3));
        try {
            regexes.emplace_back(patterns.back());
        }
        catch (const std::regex_error& e) {
            std::cerr << "Invalid regex in " << filename << ": " << patterns.back() << " (" << e.what() << ")" << std::endl;
            patterns.pop_back();
            defs.pop_back();
        }
    }
    configFile.close();
    return !patterns.empty();
}

inline bool LoadAllPatterns() {
    bool success = true;
    if (!LoadPatternsFromFile("lua_patterns.txt", LuaCheckPatterns, LuaCheckDefs, LuaCheckRegex)) success = false;
    if (!LoadPatternsFromFile("vmt_patterns.txt", VMTRegexPatterns, VMTRegexDefs, VMTRegexPatternsRegex)) success = false;
    if (!LoadPatternsFromFile("vtf_patterns.txt", VTFRegexPatterns, VTFRegexDefs, VTFRegexPatternsRegex)) success = false;
    if (!LoadPatternsFromFile("ttf_patterns.txt", TTFRegexPatterns, TTFRegexDefs, TTFRegexPatternsRegex)) success = false;
    return success;
}