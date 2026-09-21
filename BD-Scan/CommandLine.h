#pragma once
#include "Console.h"
#include <cstdint>
#include <filesystem>
#include <set>
#include <string>

#ifdef _WIN32
using NativeChar = wchar_t;
#else
using NativeChar = char;
#endif
using NativeString = std::basic_string<NativeChar>;

constexpr const char* kScannerVersion = "2.2.0";

struct ScanOptions {
    std::filesystem::path target;
    std::filesystem::path outputDir = ".";
    std::filesystem::path ruleDir;
    std::filesystem::path cacheFile;
    std::string minSeverity = "low";
    std::set<std::string> excludedTags;
    uint64_t archiveMemoryBytes = 1024ull * 1024 * 1024;
    std::string accept;
    std::string reason;
    std::string workshop;
    con::Mode colour = con::Mode::Auto;
    bool quiet = false;
    bool html = false;
    bool sarif = false;
    bool diff = false;
    bool help = false;
    bool version = false;
};

bool ParseCommandLine(int argc, const NativeChar* argv[], ScanOptions& options, std::string& error);
bool ParseInteractiveLine(const NativeString& line, ScanOptions& options, std::string& error);
NativeString ReadInputLine();
void PrintUsage();
