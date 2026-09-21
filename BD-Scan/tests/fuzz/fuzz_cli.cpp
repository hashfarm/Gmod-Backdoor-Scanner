#include "CommandLine.h"
#include "Report.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

static NativeString Widen(const std::string& value) {
    NativeString out;
    out.reserve(value.size());
    for (char c : value) out += static_cast<NativeChar>(static_cast<unsigned char>(c));
    return out;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 1 << 16) return 0;

    const std::string input(reinterpret_cast<const char*>(data), size);

    std::vector<NativeString> tokens;
    std::string current;
    for (char c : input) {
        if (c == '\0') { tokens.push_back(Widen(current)); current.clear(); }
        else current += c;
    }
    tokens.push_back(Widen(current));
    if (tokens.size() > 64) return 0;

    std::vector<const NativeChar*> argv;
    argv.push_back(nullptr);
    for (const NativeString& token : tokens) argv.push_back(token.c_str());

    ScanOptions options;
    std::string error;
    const bool ok = ParseCommandLine(static_cast<int>(argv.size()), argv.data(), options, error);

    if (!ok) {
        if (error.empty()) __builtin_trap();
        return 0;
    }

    if (error.empty() == false) __builtin_trap();
    if (!IsValidSeverity(options.minSeverity)) __builtin_trap();
    if (options.archiveMemoryBytes < 64ull * 1024 * 1024) __builtin_trap();

    for (const std::string& tag : options.excludedTags) {
        if (tag.empty()) __builtin_trap();
        if (tag.find(',') != std::string::npos) __builtin_trap();
    }

    if (!options.workshop.empty()) {
        for (char c : options.workshop) {
            if (c < '0' || c > '9') __builtin_trap();
        }
    }

    ScanOptions interactive;
    std::string other;
    ParseInteractiveLine(Widen(input), interactive, other);

    return 0;
}
