#include "Rules.h"
#include "Composite.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

static std::vector<std::string> SplitLines(const std::string& input) {
    std::vector<std::string> lines;
    std::string current;
    for (char c : input) {
        if (c == '\n') {
            lines.push_back(current);
            current.clear();
        }
        else if (c != '\r') {
            current += c;
        }
    }
    lines.push_back(current);
    return lines;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 1 << 16) return 0;

    const std::vector<std::string> lines =
        SplitLines(std::string(reinterpret_cast<const char*>(data), size));

    PatternSet patterns;
    patterns.LoadGroupFromLines(lines, { ".lua" }, "fuzz_patterns.txt");
    patterns.LoadGroupFromLines(lines, { ".vmt", ".vtf", ".ttf" }, "fuzz_binary.txt");

    for (const std::string& id : patterns.Ids()) {
        if (id.empty()) abort();
    }

    Whitelist whitelist;
    whitelist.LoadFromLines(lines);
    whitelist.IsSuppressed("lua/autorun/server/init.lua", "LUA-001");
    whitelist.IsFileWhitelisted("lua/autorun/server/init.lua", std::string(64, 'a'));

    CompositeRuleSet composites;
    composites.LoadFromLines(lines, patterns, "fuzz_composites.txt");

    return 0;
}
