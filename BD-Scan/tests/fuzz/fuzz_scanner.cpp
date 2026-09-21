#define _CRT_SECURE_NO_WARNINGS
#include "Rules.h"
#include "Scanner.h"
#include "Heuristics.h"
#include "BinaryStrings.h"
#include "Report.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

static PatternSet g_patterns;
static bool g_loaded = false;

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
    (void)argc;
    (void)argv;
    const char* rules = std::getenv("BD_SCAN_RULES");
    g_loaded = g_patterns.LoadFromDirectory(rules != nullptr ? rules : "BD-Scan");
    if (!g_loaded) {
        std::cerr << "fuzz_scanner: could not load patterns (set BD_SCAN_RULES)" << std::endl;
        std::abort();
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string input(reinterpret_cast<const char*>(data), size);

    const std::string stripped = StripLuaComments(input);
    if (stripped.size() != input.size()) __builtin_trap();
    for (size_t i = 0; i < input.size(); ++i) {
        const bool newlineIn = (input[i] == '\n');
        const bool newlineOut = (stripped[i] == '\n');
        if (newlineIn != newlineOut) __builtin_trap();
    }

    std::string folded;
    if (FoldLiterals(stripped, folded)) {
        size_t newlinesIn = 0, newlinesOut = 0;
        for (char c : stripped) newlinesIn += (c == '\n');
        for (char c : folded) newlinesOut += (c == '\n');
        if (newlinesIn != newlinesOut) __builtin_trap();
    }

    const char* extensions[] = { ".lua", ".vmt" };
    const char* extension = extensions[size % 2];

    Scanner scanner(g_patterns);
    const LineIndex index(input);
    scanner.Scan(input, "fuzz", extension, [&](const Detection& detection) {
        if (detection.lineNumber < 1) __builtin_trap();
        if (detection.contextStart < 1 || detection.contextStart > detection.lineNumber) __builtin_trap();
        if (detection.context.size() > static_cast<size_t>(2 * Scanner::kContextLines + 1)) __builtin_trap();
        if (detection.id.empty() && detection.detection.empty()) __builtin_trap();
    });

    int structural = 0;
    CollectStructuralSignals(input, extension, [&](const Detection& detection) {
        structural++;
        if (!IsStructuralSignalId(detection.id)) __builtin_trap();
        if (!IsValidSeverity(detection.severity)) __builtin_trap();
        if (detection.lineNumber < 0) __builtin_trap();
        if (detection.hint.empty()) __builtin_trap();
    });
    if (structural > static_cast<int>(StructuralSignals().size())) __builtin_trap();
    if (structural > 0 && extension != std::string(".lua")) __builtin_trap();

    const double bits = heuristics::ShannonEntropy(input);
    if (bits < 0.0 || bits > 8.0) __builtin_trap();

    const std::string runs = binstr::ExtractPrintableRuns(input);
    if (runs.size() > input.size() + 1) __builtin_trap();
    for (char c : runs) {
        if (c != 0x0a && !binstr::IsPrintableRunChar(static_cast<unsigned char>(c))) __builtin_trap();
    }
    scanner.Scan(runs, "fuzz.dll", ".dll", [&](const Detection& detection) {
        if (detection.id.empty() && detection.detection.empty()) __builtin_trap();
    });

    return 0;
}
