#pragma once
#include <string>
#include <vector>
#include <map>
#include <set>
#include <fstream>
#include <iostream>
#include <regex>
#include <algorithm>
#include <filesystem>

#include "CleanString.h"
#include "Prefilter.h"

inline std::filesystem::path ResolveDataFile(const std::filesystem::path& baseDir, const std::string& filename) {
    return baseDir / filename;
}

inline std::string PathText(const std::filesystem::path& path) {
    const auto encoded = path.u8string();
    return std::string(encoded.begin(), encoded.end());
}

inline std::string ToLowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
    });
    return value;
}

inline std::string ToUpperAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(c >= 'a' && c <= 'z' ? c - 'a' + 'A' : c);
    });
    return value;
}

inline std::string ElideRuleText(const std::string& value, size_t limit = 120) {
    if (value.size() <= limit) return SanitizeUtf8(value);
    return SanitizeUtf8(value.substr(0, limit)) + "... (" + std::to_string(value.size()) + " bytes)";
}

inline std::string TrimAscii(const std::string& value) {
    const size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

inline bool ReadRuleLines(const std::filesystem::path& path, std::vector<std::string>& lines, bool reportMissing) {
    std::ifstream file(path);
    if (!file.is_open()) {
        if (reportMissing) {
            std::cerr << "Error: Could not open rule file: " << PathText(path) << std::endl;
        }
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
    }
    return !file.bad();
}

inline std::string SeverityFromDefinition(const std::string& definition) {
    if (definition.find("[CRITICAL]") != std::string::npos) return "critical";
    if (definition.find("[HIGH]") != std::string::npos) return "high";
    if (definition.find("[MEDIUM]") != std::string::npos) return "medium";
    if (definition.find("[LOW]") != std::string::npos) return "low";
    return "";
}

inline std::string IdFromDefinition(const std::string& definition) {
    const size_t close = definition.find(']');
    const size_t start = definition.find_first_not_of(" \t", close == std::string::npos ? 0 : close + 1);
    if (start == std::string::npos) return "";

    size_t end = definition.find_first_of(" \t", start);
    if (end == std::string::npos) end = definition.size();

    const std::string token = definition.substr(start, end - start);
    static const std::regex idFormat(R"([A-Z]{2,6}-[0-9]{1,4})");
    return std::regex_match(token, idFormat) ? token : "";
}

// libstdc++ overflows the stack compiling a huge pattern; longest shipped is 250.
constexpr size_t kMaxRuleExpression = 4000;

// (a+)+ : MSVC throws, libstdc++ never returns. A bounded inner repeat is left alone.
inline bool AmbiguousAlternation(const std::string& body) {
    size_t from = 0;
    if (!body.empty() && body[0] == '?') {
        const size_t colon = body.find(':');
        if (colon == std::string::npos) return false;
        from = colon + 1;
    }

    std::vector<std::string> branches;
    size_t start = from;
    int depth = 0;
    for (size_t i = from; i < body.size(); ++i) {
        if (body[i] == '\\') { i++; continue; }
        if (body[i] == '[') {
            while (i < body.size() && body[i] != ']') {
                if (body[i] == '\\') i++;
                i++;
            }
            continue;
        }
        if (body[i] == '(') depth++;
        else if (body[i] == ')') depth--;
        else if (body[i] == '|' && depth == 0) {
            branches.push_back(body.substr(start, i - start));
            start = i + 1;
        }
    }
    if (branches.empty()) return false;
    branches.push_back(body.substr(start));

    std::set<char> firsts;
    for (const std::string& branch : branches) {
        size_t at = 0;
        while (at < branch.size() && (branch[at] == '(' || branch[at] == ':')) at++;
        if (at < branch.size() && branch[at] == '?') {
            const size_t colon = branch.find(':', at);
            at = colon == std::string::npos ? branch.size() : colon + 1;
        }
        if (at >= branch.size()) return true;
        const char c = branch[at];
        if (c == '\\' || c == '[' || c == '.' || c == '^' || c == '$') continue;
        if (!firsts.insert(c).second) return true;
    }
    return false;
}

inline bool RepeatsARepeat(const std::string& expression) {
    auto quantifierAt = [&](size_t at) -> size_t {
        if (at >= expression.size()) return 0;
        const char c = expression[at];
        if (c == '+' || c == '*') return 1;
        if (c != '{') return 0;
        const size_t close = expression.find('}', at);
        if (close == std::string::npos) return 0;
        const std::string body = expression.substr(at + 1, close - at - 1);
        return body.find(',') != std::string::npos && body.back() == ',' ? close - at + 1 : 0;
    };

    for (size_t i = 0; i < expression.size(); ++i) {
        if (expression[i] == '\\') { i++; continue; }
        if (expression[i] != ')' || quantifierAt(i + 1) == 0) continue;

        int depth = 0;
        size_t open = i;
        while (open > 0) {
            open--;
            if (open > 0 && expression[open - 1] == '\\') continue;
            if (expression[open] == ')') depth++;
            else if (expression[open] == '(') {
                if (depth == 0) break;
                depth--;
            }
        }
        if (expression[open] != '(') continue;

        if (AmbiguousAlternation(expression.substr(open + 1, i - open - 1))) return true;

        for (size_t j = open + 1; j < i; ++j) {
            if (expression[j] == '\\') { j++; continue; }
            if (expression[j] == '[') {
                while (j < i && expression[j] != ']') {
                    if (expression[j] == '\\') j++;
                    j++;
                }
                continue;
            }
            if (quantifierAt(j) != 0) return true;
        }
    }
    return false;
}

inline std::regex GlobToRegex(const std::string& glob) {
    if (glob.size() > kMaxRuleExpression) {
        throw std::regex_error(std::regex_constants::error_complexity);
    }
    std::string expression;
    expression.reserve(glob.size() * 2);
    for (char c : glob) {
        switch (c) {
            case '*': expression += ".*"; break;
            case '?': expression += '.';  break;
            case '\\':
            case '/': expression += "[\\\\/]"; break;
            case '.': case '+': case '(': case ')': case '[': case ']':
            case '{': case '}': case '^': case '$': case '|':
                expression += '\\';
                expression += c;
                break;
            default: expression += c; break;
        }
    }
    // A glob of stars expands to twice its length, and how much the engine takes
    // before it gives up differs between compilers. Measure what is built.
    if (expression.size() > kMaxRuleExpression) {
        throw std::regex_error(std::regex_constants::error_complexity);
    }
    return std::regex(expression, std::regex::ECMAScript | std::regex::icase | std::regex::optimize);
}

struct Pattern {
    std::regex regex;
    std::string expression;
    std::string definition;
    std::string severity;
    std::string id;
    std::string hint;

    std::string pathGlob;
    std::vector<std::regex> pathRegexes;
    bool hasPathScope = false;
    std::set<std::string> tags;
    std::string reference;
    std::string added;
    std::vector<size_t> requiredLiterals;

    bool AppliesTo(const std::string& filePath) const {
        if (!hasPathScope) return true;
        for (const std::regex& candidate : pathRegexes) {
            if (std::regex_match(filePath, candidate)) return true;
        }
        return false;
    }
};

inline std::vector<std::string> SplitGlobs(const std::string& text) {
    std::vector<std::string> globs;
    std::string token;
    for (char c : text) {
        if (c == ',') {
            if (!token.empty()) { globs.push_back(token); token.clear(); }
        }
        else token += c;
    }
    if (!token.empty()) globs.push_back(token);
    return globs;
}

inline std::map<std::string, std::string> ParseAttributes(const std::string& text) {
    std::map<std::string, std::string> attributes;
    std::string token;

    auto flush = [&]() {
        if (token.empty()) return;
        const size_t equals = token.find('=');
        if (equals != std::string::npos && equals > 0) {
            attributes[token.substr(0, equals)] = token.substr(equals + 1);
        }
        token.clear();
    };

    for (char c : text) {
        if (std::isspace(static_cast<unsigned char>(c))) flush();
        else token += c;
    }
    flush();
    return attributes;
}

inline std::string SamplePathForGlob(const std::string& glob, const std::string& fallback) {
    if (glob.empty()) return fallback;

    const std::vector<std::string> globs = SplitGlobs(glob);
    if (globs.empty()) return fallback;

    std::string path;
    for (char c : globs.front()) {
        if (c == '*' || c == '?') path += 'x';
        else path += c;
    }
    return path;
}

inline std::string ExpandRuleMacros(std::string expression) {
    static const std::string call = "%CALL%";
    static const std::string opens =
        R"((?:\(|"[^"\r\n]*"|'[^'\r\n]*'|\[=*\[))";
    for (size_t at = expression.find(call); at != std::string::npos;
         at = expression.find(call, at + opens.size())) {
        expression.replace(at, call.size(), opens);
    }
    return expression;
}

inline std::set<std::string> SplitTags(const std::string& text) {
    std::set<std::string> tags;
    std::string token;
    for (char c : text) {
        if (c == ',') {
            const std::string trimmed = TrimAscii(token);
            if (!trimmed.empty()) tags.insert(ToLowerAscii(trimmed));
            token.clear();
        }
        else token += c;
    }
    const std::string trimmed = TrimAscii(token);
    if (!trimmed.empty()) tags.insert(ToLowerAscii(trimmed));
    return tags;
}

class PatternSet {
public:
    bool LoadFromDirectory(const std::filesystem::path& baseDir) {
        m_groups.clear();
        m_extensionToGroup.clear();
        m_rawContent.clear();
        m_automaton = AhoCorasick();
        if (!LoadGroup(ResolveDataFile(baseDir, "lua_patterns.txt"), { ".lua" }) ||
            !LoadGroup(ResolveDataFile(baseDir, "binary_patterns.txt"), { ".vmt", ".vtf", ".ttf" }) ||
            !LoadGroup(ResolveDataFile(baseDir, "data_patterns.txt"), { ".txt", ".dat", ".json" }) ||
            !LoadGroup(ResolveDataFile(baseDir, "module_patterns.txt"), { ".dll", ".so", ".dylib" })) {
            m_groups.clear();
            m_extensionToGroup.clear();
            m_rawContent.clear();
            return false;
        }
        BuildPrefilter();
        return true;
    }

    bool LoadGroup(const std::filesystem::path& path, const std::vector<std::string>& extensions) {
        std::vector<std::string> lines;
        if (!ReadRuleLines(path, lines, true)) return false;
        return LoadGroupFromLines(lines, extensions, PathText(path.filename()));
    }

    bool LoadGroupFromLines(const std::vector<std::string>& lines,
                            const std::vector<std::string>& extensions,
                            const std::string& label) {
        for (const std::string& line : lines) {
            if (line.empty() || line[0] == '#') continue;
            m_rawContent += line;
            m_rawContent += '\n';
        }

        std::vector<Pattern> patterns;
        std::set<std::string> seenIds;

        for (size_t i = 0; i < lines.size(); ++i) {
            const std::string& line = lines[i];
            if (line.empty() || line[0] == '#') continue;

            const size_t separator = line.find(";;;");
            if (separator == std::string::npos) {
                std::cerr << "Error: Missing ';;;' separator in " << label
                          << " line " << (i + 1) << ": " << ElideRuleText(line) << std::endl;
                return false;
            }

            Pattern pattern;
            std::vector<std::string> fields;
            {
                std::string remainder = line.substr(separator + 3);
                size_t next;
                while ((next = remainder.find(";;;")) != std::string::npos) {
                    fields.push_back(TrimAscii(remainder.substr(0, next)));
                    remainder = remainder.substr(next + 3);
                }
                fields.push_back(TrimAscii(remainder));
            }

            pattern.definition = fields[0];
            if (fields.size() > 1) pattern.hint = fields[1];
            if (fields.size() > 3) {
                std::cerr << "Error: " << label << " line " << (i + 1)
                          << " has " << fields.size() << " fields after the regex; only the first"
                          << " three are read. Attributes go in one field, separated by spaces."
                          << std::endl;
                return false;
            }
            if (fields.size() > 2) {
                const std::map<std::string, std::string> attributes = ParseAttributes(fields[2]);
                for (const auto& attribute : attributes) {
                    if (attribute.first == "path") {
                        pattern.pathGlob = attribute.second;
                        const std::vector<std::string> globs = SplitGlobs(pattern.pathGlob);
                        if (globs.empty()) {
                            std::cerr << "Error: Empty path glob in " << label << " line " << (i + 1) << std::endl;
                            return false;
                        }
                        try {
                            for (const std::string& glob : globs) {
                                pattern.pathRegexes.push_back(GlobToRegex(glob));
                            }
                            pattern.hasPathScope = true;
                        }
                        catch (const std::regex_error&) {
                            std::cerr << "Error: Invalid path glob in " << label << " line " << (i + 1)
                                      << ": " << ElideRuleText(pattern.pathGlob) << std::endl;
                            return false;
                        }
                    }
                    else if (attribute.first == "tags") pattern.tags = SplitTags(attribute.second);
                    else if (attribute.first == "ref") pattern.reference = attribute.second;
                    else if (attribute.first == "added") pattern.added = attribute.second;
                    else {
                        std::cerr << "Error: Unknown attribute '" << attribute.first << "' in "
                                  << label << " line " << (i + 1) << std::endl;
                        return false;
                    }
                }
            }
            pattern.severity = SeverityFromDefinition(pattern.definition);
            if (pattern.severity.empty()) {
                std::cerr << "Error: No severity tag in " << label << " line " << (i + 1)
                          << ": " << pattern.definition << std::endl;
                return false;
            }

            pattern.id = IdFromDefinition(pattern.definition);
            if (pattern.id.empty() || !seenIds.insert(pattern.id).second || ById(pattern.id) != nullptr) {
                std::cerr << "Error: Missing or duplicate pattern id " << pattern.id << " in " << label
                          << " line " << (i + 1) << std::endl;
                return false;
            }

            pattern.expression = ExpandRuleMacros(line.substr(0, separator));
            const std::string& expression = pattern.expression;
            if (RepeatsARepeat(expression)) {
                std::cerr << "Error: Pattern in " << label << " line " << (i + 1)
                          << " repeats a group that can match the same text more than one way: "
                          << ElideRuleText(expression) << std::endl
                          << "Matching that can take longer than the age of the server. "
                          << "Bound the outer repeat, drop the group, or make the branches "
                          << "start differently."
                          << std::endl;
                return false;
            }
            if (expression.size() > kMaxRuleExpression) {
                std::cerr << "Error: Pattern in " << label << " line " << (i + 1) << " is "
                          << expression.size() << " characters; the limit is " << kMaxRuleExpression
                          << ". A regex that long crashes the compiler on some platforms."
                          << std::endl;
                return false;
            }
            try {
                pattern.regex = std::regex(expression, std::regex::ECMAScript | std::regex::optimize);
            }
            catch (const std::regex_error& e) {
                std::cerr << "Invalid regex in " << label << " line " << (i + 1) << ": "
                          << ElideRuleText(expression) << " (" << e.what() << ")" << std::endl;
                return false;
            }

            patterns.push_back(std::move(pattern));
        }

        if (patterns.empty()) {
            std::cerr << "Error: No usable patterns in " << label << std::endl;
            return false;
        }

        m_groups.push_back(std::move(patterns));
        for (const std::string& extension : extensions) {
            m_extensionToGroup[extension] = m_groups.size() - 1;
        }
        return true;
    }

    const std::vector<Pattern>* ForExtension(const std::string& extension) const {
        const auto it = m_extensionToGroup.find(extension);
        if (it == m_extensionToGroup.end()) return nullptr;
        return &m_groups[it->second];
    }

    const Pattern* ById(const std::string& id) const {
        for (const std::vector<Pattern>& group : m_groups) {
            for (const Pattern& pattern : group) {
                if (pattern.id == id) return &pattern;
            }
        }
        return nullptr;
    }

    std::vector<std::string> Extensions() const {
        std::vector<std::string> result;
        for (const auto& entry : m_extensionToGroup) result.push_back(entry.first);
        return result;
    }

    std::vector<std::string> Ids() const {
        std::vector<std::string> result;
        for (const std::vector<Pattern>& group : m_groups) {
            for (const Pattern& pattern : group) {
                if (!pattern.id.empty()) result.push_back(pattern.id);
            }
        }
        return result;
    }

    size_t Count() const {
        size_t total = 0;
        for (const auto& group : m_groups) total += group.size();
        return total;
    }

    const std::string& RawContent() const { return m_rawContent; }
    const AhoCorasick& Automaton() const { return m_automaton; }

    void BuildPrefilter() {
        for (std::vector<Pattern>& group : m_groups) {
            for (Pattern& pattern : group) {
                for (const std::string& literal : LiteralExtractor::Required(pattern.expression)) {
                    pattern.requiredLiterals.push_back(m_automaton.Add(literal));
                }
            }
        }
        m_automaton.Build();
    }

    size_t PrefilteredPatternCount() const {
        size_t total = 0;
        for (const std::vector<Pattern>& group : m_groups) {
            for (const Pattern& pattern : group) {
                if (!pattern.requiredLiterals.empty()) total++;
            }
        }
        return total;
    }

private:
    AhoCorasick m_automaton;
    std::string m_rawContent;
    std::vector<std::vector<Pattern>> m_groups;
    std::map<std::string, size_t> m_extensionToGroup;
};

struct PatternTest {
    bool expectMatch = true;
    std::string id;
    std::string snippet;
    std::string extension;
    int lineNumber = 0;
};

inline std::string UnescapeSnippet(const std::string& value) {
    std::string result;
    result.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '\\' && i + 1 < value.size()) {
            const char next = value[i + 1];
            if (next == 'n') { result += '\n'; i++; continue; }
            if (next == 't') { result += '\t'; i++; continue; }
            if (next == '\\') { result += '\\'; i++; continue; }
        }
        result += value[i];
    }
    return result;
}

inline bool LoadPatternTests(const std::filesystem::path& path, const std::string& extension,
                             std::vector<PatternTest>& tests) {
    std::vector<std::string> lines;
    if (!ReadRuleLines(path, lines, true)) return false;

    for (size_t i = 0; i < lines.size(); ++i) {
        const std::string& line = lines[i];
        if (line.empty() || line[0] == '#') continue;

        if (line[0] != '+' && line[0] != '-') {
            std::cerr << "Warning: Test line must start with + or - in " << PathText(path.filename())
                      << " line " << (i + 1) << ": " << ElideRuleText(line) << std::endl;
            continue;
        }

        const size_t separator = line.find(";;;");
        if (separator == std::string::npos) {
            std::cerr << "Warning: Missing ';;;' separator in " << PathText(path.filename())
                      << " line " << (i + 1) << ": " << ElideRuleText(line) << std::endl;
            continue;
        }

        PatternTest test;
        test.expectMatch = (line[0] == '+');
        test.id = TrimAscii(line.substr(1, separator - 1));
        test.snippet = UnescapeSnippet(TrimAscii(line.substr(separator + 3)));
        test.extension = extension;
        test.lineNumber = static_cast<int>(i + 1);

        if (test.id.empty() || test.snippet.empty()) {
            std::cerr << "Warning: Empty id or snippet in " << PathText(path.filename())
                      << " line " << (i + 1) << std::endl;
            continue;
        }
        tests.push_back(std::move(test));
    }
    return !tests.empty();
}

inline bool IsSha256Hex(const std::string& value) {
    if (value.size() != 64) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

inline size_t LoadHashList(const std::filesystem::path& path, std::set<std::string>& target,
                           std::vector<std::string>* rejected = nullptr) {
    std::vector<std::string> lines;
    if (!ReadRuleLines(path, lines, false)) return 0;

    size_t added = 0;
    for (const std::string& line : lines) {
        if (line.empty() || line[0] == '#') continue;
        const size_t separator = line.find(";;;");
        const std::string hash = ToLowerAscii(TrimAscii(separator == std::string::npos ? line : line.substr(0, separator)));
        if (hash.empty()) continue;
        if (!IsSha256Hex(hash)) {
            if (rejected != nullptr) rejected->push_back(ElideRuleText(line));
            continue;
        }
        if (target.insert(hash).second) added++;
    }
    return added;
}

class Whitelist {
public:
    size_t Load(const std::filesystem::path& path) {
        std::vector<std::string> lines;
        if (!ReadRuleLines(path, lines, false)) return 0;
        return LoadFromLines(lines);
    }

    size_t LoadFromLines(const std::vector<std::string>& lines) {
        size_t added = 0;
        for (const std::string& line : lines) {
            if (line.empty() || line[0] == '#') continue;

            const size_t separator = line.find(";;;");
            const std::string left = TrimAscii(separator == std::string::npos ? line : line.substr(0, separator));
            const std::string right = separator == std::string::npos ? "" : TrimAscii(line.substr(separator + 3));

            if (right.empty() && IsHash(left)) {
                if (m_hashes.insert(ToLowerAscii(left)).second) added++;
                continue;
            }

            if (IsHash(right)) {
                PinnedFile pinned;
                pinned.pathGlob = left.empty() ? "*" : left;
                pinned.hash = ToLowerAscii(right);
                try {
                    pinned.pathRegex = GlobToRegex(pinned.pathGlob);
                }
                catch (const std::regex_error&) {
                    std::cerr << "Warning: Invalid whitelist path pattern: "
                              << ElideRuleText(pinned.pathGlob) << std::endl;
                    continue;
                }
                m_pinned.push_back(std::move(pinned));
                added++;
                continue;
            }

            Suppression suppression;
            suppression.pathGlob = left.empty() ? "*" : left;
            suppression.detectionSubstring = right;
            try {
                suppression.pathRegex = GlobToRegex(suppression.pathGlob);
            }
            catch (const std::regex_error&) {
                std::cerr << "Warning: Invalid whitelist path pattern: "
                          << ElideRuleText(suppression.pathGlob) << std::endl;
                continue;
            }
            m_suppressions.push_back(std::move(suppression));
            added++;
        }
        return added;
    }

    bool IsFileWhitelisted(const std::string& hash) const {
        return m_hashes.find(hash) != m_hashes.end();
    }

    bool IsFileWhitelisted(const std::string& filePath, const std::string& hash) const {
        if (IsFileWhitelisted(hash)) return true;
        const std::string lowered = ToLowerAscii(hash);
        for (const PinnedFile& pinned : m_pinned) {
            if (pinned.hash != lowered) continue;
            if (std::regex_match(filePath, pinned.pathRegex)) return true;
        }
        return false;
    }

    bool IsSuppressed(const std::string& filePath, const std::string& detection) const {
        for (const Suppression& suppression : m_suppressions) {
            if (!suppression.detectionSubstring.empty() &&
                detection.find(suppression.detectionSubstring) == std::string::npos) {
                continue;
            }
            if (std::regex_match(filePath, suppression.pathRegex)) {
                suppression.hits++;
                return true;
            }
        }
        return false;
    }

    struct Entry {
        std::string text;
        int hits;
    };

    std::vector<Entry> PathRules() const {
        std::vector<Entry> result;
        for (const Suppression& suppression : m_suppressions) {
            std::string text = suppression.pathGlob;
            if (!suppression.detectionSubstring.empty()) text += ";;;" + suppression.detectionSubstring;
            result.push_back({ text, suppression.hits });
        }
        return result;
    }

    bool Empty() const {
        return m_hashes.empty() && m_suppressions.empty() && m_pinned.empty();
    }

    size_t HashCount() const { return m_hashes.size(); }

    std::vector<std::string> Hashes() const {
        std::vector<std::string> result(m_hashes.begin(), m_hashes.end());
        for (const PinnedFile& pinned : m_pinned) result.push_back(pinned.hash);
        return result;
    }
    size_t RuleCount() const { return m_suppressions.size(); }
    size_t PinnedCount() const { return m_pinned.size(); }

private:
    struct Suppression {
        std::string pathGlob;
        std::string detectionSubstring;
        std::regex pathRegex;
        mutable int hits = 0;
    };

    struct PinnedFile {
        std::string pathGlob;
        std::string hash;
        std::regex pathRegex;
    };

    static bool IsHash(const std::string& value) { return IsSha256Hex(value); }

    std::set<std::string> m_hashes;
    std::vector<Suppression> m_suppressions;
    std::vector<PinnedFile> m_pinned;
};
