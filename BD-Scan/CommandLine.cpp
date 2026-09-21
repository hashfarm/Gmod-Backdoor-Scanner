#include "CommandLine.h"
#include "Report.h"
#include <cctype>
#include <cwctype>
#include <iostream>
#include <limits>
#include <type_traits>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace {
std::string OptionText(const NativeString& value) {
    std::string result;
    for (NativeChar c : value) {
        const auto code = static_cast<std::make_unsigned<NativeChar>::type>(c);
        result += (code > 0 && code < 128) ? static_cast<char>(code) : '?';
    }
    return result;
}

std::string OptionValue(const NativeString& value) {
#ifdef _WIN32
    if (value.empty()) return std::string();
    const int needed = WideCharToMultiByte(CP_UTF8, 0, value.c_str(),
                                           static_cast<int>(value.size()),
                                           nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return OptionText(value);
    std::string result(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()),
                        &result[0], needed, nullptr, nullptr);
    return result;
#else
    return value;
#endif
}

bool ParseTokens(const std::vector<NativeString>& tokens, bool interactive,
                 ScanOptions& options, std::string& error) {
    for (size_t i = 0; i < tokens.size(); ++i) {
        const std::string arg = OptionText(tokens[i]);
        if (arg == "--html") options.html = true;
        else if (arg == "--sarif") options.sarif = true;
        else if (arg == "--diff") options.diff = true;
        else if (arg == "-q" || arg == "--quiet") options.quiet = true;
        else if (arg == "-h" || arg == "--help") options.help = true;
        else if (arg == "--version") options.version = true;
        else if (arg == "-d" || arg == "-o" || arg == "--rules" || arg == "-s" ||
                 arg == "--exclude-tags" || arg == "--memory-limit" || arg == "--color" ||
                 arg == "--accept" || arg == "--reason" || arg == "--cache" ||
                 arg == "--workshop") {
            if (i + 1 == tokens.size() || tokens[i + 1].empty() || tokens[i + 1][0] == static_cast<NativeChar>('-')) {
                error = "Missing value for " + arg;
                return false;
            }
            const NativeString& value = tokens[++i];
            if (arg == "-d") options.target = value;
            else if (arg == "-o") options.outputDir = value;
            else if (arg == "--rules") options.ruleDir = value;
            else if (arg == "-s") options.minSeverity = OptionText(value);
            else if (arg == "--exclude-tags") {
                for (const std::string& tag : SplitTags(OptionText(value))) options.excludedTags.insert(tag);
            }
            else if (arg == "--accept") options.accept = OptionValue(value);
            else if (arg == "--reason") options.reason = OptionValue(value);
            else if (arg == "--cache") options.cacheFile = value;
            else if (arg == "--workshop") {
                options.workshop = OptionText(value);
                if (options.workshop.empty() ||
                    options.workshop.find_first_not_of("0123456789") != std::string::npos) {
                    error = "--workshop takes the numeric id from the Workshop URL, for example 104604709";
                    return false;
                }
            }
            else if (arg == "--color") {
                const std::string text = OptionText(value);
                if (text == "auto") options.colour = con::Mode::Auto;
                else if (text == "always") options.colour = con::Mode::Always;
                else if (text == "never") options.colour = con::Mode::Never;
                else {
                    error = "--color must be auto, always or never";
                    return false;
                }
            }
            else {
                const std::string text = OptionText(value);
                uint64_t mib = 0;
                for (char c : text) {
                    if (c < '0' || c > '9' || mib > 1048576) {
                        error = "--memory-limit must be an integer between 64 and 1048576 MiB";
                        return false;
                    }
                    mib = mib * 10 + static_cast<unsigned>(c - '0');
                }
                if (mib < 64 || mib > 1048576 || mib > std::numeric_limits<size_t>::max() / (1024ull * 1024)) {
                    error = "--memory-limit is outside the supported range";
                    return false;
                }
                options.archiveMemoryBytes = mib * 1024 * 1024;
            }
        }
        else if (interactive && !arg.empty() && arg[0] != '-') {
            if (options.target.empty()) options.target = tokens[i];
            else options.target = options.target.native() + NativeString(1, static_cast<NativeChar>(' ')) + tokens[i];
        }
        else {
            error = "Unknown argument: " + arg;
            return false;
        }
    }
    if (!IsValidSeverity(options.minSeverity)) {
        error = "Invalid severity '" + options.minSeverity + "'. Use low, medium, high or critical.";
        return false;
    }
    return true;
}
}

bool ParseCommandLine(int argc, const NativeChar* argv[], ScanOptions& options, std::string& error) {
    std::vector<NativeString> tokens;
    for (int i = 1; i < argc; ++i) tokens.emplace_back(argv[i]);
    return ParseTokens(tokens, false, options, error);
}

bool ParseInteractiveLine(const NativeString& line, ScanOptions& options, std::string& error) {
    std::vector<NativeString> tokens;
    NativeString current;
    bool quoted = false;
    for (NativeChar c : line) {
        if (c == static_cast<NativeChar>('"')) { quoted = !quoted; continue; }
#ifdef _WIN32
        const bool space = std::iswspace(static_cast<wint_t>(c)) != 0;
#else
        const bool space = std::isspace(static_cast<unsigned char>(c)) != 0;
#endif
        if (!quoted && space) {
            if (!current.empty()) { tokens.push_back(current); current.clear(); }
        }
        else current += c;
    }
    if (quoted) { error = "Unclosed quote in input"; return false; }
    if (!current.empty()) tokens.push_back(current);
    return ParseTokens(tokens, true, options, error);
}

void PrintUsage() {
    std::cout << "Usage: BD-Scan.exe [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -d <path>         Directory to scan recursively, or a single file" << std::endl;
    std::cout << "  --workshop <id>   Scan a Workshop item: a subscribed copy, or via steamcmd" << std::endl;
    std::cout << "  -o <directory>    Where to write scan_log.json, last_scan.json and scan_report.html (default: current directory)" << std::endl;
    std::cout << "  --rules <dir>     Load the rule files from here instead of searching for them" << std::endl;
    std::cout << "  -s <severity>     Minimum severity level (low/medium/high/critical)" << std::endl;
    std::cout << "  --exclude-tags a,b Skip patterns carrying any of these tags (for example: darkrp)" << std::endl;
    std::cout << "  --memory-limit <MiB> Shared archive buffer budget (default: 1024, minimum: 64)" << std::endl;
    std::cout << "  --color <when>    auto (default), always or never" << std::endl;
    std::cout << "  --accept <rule>@<glob>  Record a finding as reviewed in whitelist.txt" << std::endl;
    std::cout << "  --reason <text>   Why it is fine; stored next to the entry" << std::endl;
    std::cout << "  --cache <file>    Reuse results for files whose SHA-256 is unchanged" << std::endl;
    std::cout << "  -q, --quiet       Quiet mode (only show summary)" << std::endl;
    std::cout << "  --html            Generate HTML report" << std::endl;
    std::cout << "  --sarif           Write scan_results.sarif for CI code scanning" << std::endl;
    std::cout << "  --diff            Report only NEW detections since the last full scan" << std::endl;
    std::cout << "  -h, --help        Show this help message" << std::endl;
    std::cout << "  --version         Print the version and the rule fingerprint" << std::endl;
    std::cout << std::endl;
    std::cout << "Exit codes:" << std::endl;
    std::cout << "  0                 No detections, everything was examined" << std::endl;
    std::cout << "  1                 Detections reported" << std::endl;
    std::cout << "  2                 Error (bad arguments, unreadable path, missing patterns)" << std::endl;
    std::cout << "  3                 No detections, but some files could not be examined" << std::endl;
    std::cout << std::endl;
    std::cout << "Rule files (--rules, else next to the executable, else the working directory):" << std::endl;
    std::cout << "  lua_patterns.txt     Patterns for .lua files" << std::endl;
    std::cout << "  binary_patterns.txt  Patterns for .vmt, .vtf and .ttf files" << std::endl;
    std::cout << "  data_patterns.txt    Patterns for .txt, .dat and .json under data/, cache/ and download/" << std::endl;
    std::cout << "  module_patterns.txt  Patterns for the strings inside .dll, .so and .dylib" << std::endl;
    std::cout << "  composite_rules.txt  File and addon combination rules (optional)" << std::endl;
    std::cout << "  known_hashes.txt     Known backdoor hashes (SHA-256)" << std::endl;
    std::cout << "  whitelist.txt        False-positive suppression" << std::endl;
    std::cout << std::endl;
    std::cout << "Output (written to the -o directory):" << std::endl;
    std::cout << "  scan_log.json        Full result of this scan" << std::endl;
    std::cout << "  last_scan.json       Baseline for --diff, written by complete, unfiltered scans only" << std::endl;
    std::cout << "  scan_report.html     Written with --html" << std::endl;
    std::cout << "  scan_results.sarif   Written with --sarif" << std::endl;
}

NativeString ReadInputLine() {
#ifdef _WIN32
    const HANDLE handle = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (handle != INVALID_HANDLE_VALUE && GetConsoleMode(handle, &mode)) {
        std::wstring buffer(4096, L'\0');
        DWORD read = 0;
        if (ReadConsoleW(handle, &buffer[0], static_cast<DWORD>(buffer.size()), &read, nullptr)) {
            buffer.resize(read);
            while (!buffer.empty() && (buffer.back() == L'\n' || buffer.back() == L'\r')) {
                buffer.pop_back();
            }
            return buffer;
        }
    }
    std::wstring line;
    std::getline(std::wcin, line);
    return line;
#else
    std::string line;
    std::getline(std::cin, line);
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
    return line;
#endif
}

