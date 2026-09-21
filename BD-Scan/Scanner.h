#pragma once
#include <string>
#include <vector>
#include <set>
#include <regex>
#include <functional>
#include <algorithm>
#include <cstdint>

#include "Rules.h"
#include "CleanString.h"

struct DetectionEvidence {
    std::string id;
    std::string file;
    int lineNumber = 0;
    std::string hash;
};

struct Detection {
    std::string file;
    std::string container;
    std::string detection;
    std::string severity;
    std::string id;
    std::string hint;
    int lineNumber = 0;
    std::string lineText;
    std::string decodedContent;
    std::string hash;
    std::string fingerprint;
    std::vector<DetectionEvidence> related;
    int contextStart = 0;
    std::vector<std::string> context;
};

inline std::string DecodeBase64(const std::string& encoded) {
    static const std::string table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string decoded;
    uint32_t accumulator = 0;
    unsigned bits = 0;

    for (char raw : encoded) {
        const size_t index = table.find(raw);
        if (index == std::string::npos) break;

        accumulator = (accumulator << 6) | static_cast<uint32_t>(index);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            decoded += static_cast<char>((accumulator >> bits) & 0xFF);
            accumulator &= (1u << bits) - 1u;
        }
    }
    return decoded;
}

inline std::string StripLuaComments(const std::string& content) {
    std::string out = content;
    const size_t n = content.size();

    auto blank = [&](size_t from, size_t to) {
        for (size_t k = from; k < to && k < n; ++k) {
            if (out[k] != '\n' && out[k] != '\r') out[k] = ' ';
        }
    };

    auto longBracketLevel = [&](size_t at, size_t& contentStart) -> bool {
        if (at >= n || content[at] != '[') return false;
        size_t k = at + 1;
        while (k < n && content[k] == '=') ++k;
        if (k < n && content[k] == '[') {
            contentStart = k + 1;
            return true;
        }
        return false;
    };

    size_t i = 0;
    while (i < n) {
        const char c = content[i];

        if (c == '"' || c == '\'') {
            const char quote = c;
            ++i;
            while (i < n) {
                if (content[i] == '\\') {
                    if (i + 1 < n && content[i + 1] == 'z') {
                        i += 2;
                        while (i < n && std::isspace(static_cast<unsigned char>(content[i]))) ++i;
                        continue;
                    }
                    i += 2;
                    continue;
                }
                if (content[i] == quote || content[i] == '\n' || content[i] == '\r') { ++i; break; }
                ++i;
            }
            continue;
        }

        if (c == '[') {
            size_t bodyStart = 0;
            if (longBracketLevel(i, bodyStart)) {
                const size_t level = bodyStart - i - 2;
                const std::string close = "]" + std::string(level, '=') + "]";
                const size_t end = content.find(close, bodyStart);
                i = (end == std::string::npos) ? n : end + close.size();
                continue;
            }
        }

        if (c == '-' && i + 1 < n && content[i + 1] == '-') {
            size_t bodyStart = 0;
            if (longBracketLevel(i + 2, bodyStart)) {
                const size_t level = bodyStart - (i + 2) - 2;
                const std::string close = "]" + std::string(level, '=') + "]";
                const size_t end = content.find(close, bodyStart);
                const size_t stop = (end == std::string::npos) ? n : end + close.size();
                blank(i, stop);
                i = stop;
            }
            else {
                size_t end = content.find_first_of("\r\n", i);
                if (end == std::string::npos) end = n;
                blank(i, end);
                i = end;
            }
            continue;
        }

        ++i;
    }
    return out;
}

inline bool IsFoldableChar(int value) {
    return value >= 32 && value <= 126 && value != '"' && value != '\'' && value != '\\';
}

template <typename Fn>
inline bool ReplaceEach(const std::string& in, const std::regex& pattern, Fn&& shouldReplace, std::string& out) {
    bool changed = false;
    size_t last = 0;
    std::string result;

    for (auto it = std::sregex_iterator(in.begin(), in.end(), pattern); it != std::sregex_iterator(); ++it) {
        const std::smatch& match = *it;
        std::string replacement;
        if (!shouldReplace(match, replacement)) continue;

        const size_t position = static_cast<size_t>(match.position(0));
        result.append(in, last, position - last);
        result += replacement;
        last = position + static_cast<size_t>(match.length(0));
        changed = true;
    }

    if (!changed) return false;
    result.append(in, last, std::string::npos);
    out.swap(result);
    return true;
}

inline std::string NewlinesIn(const std::string& text) {
    std::string result;
    for (char c : text) {
        if (c == '\n') result += '\n';
    }
    return result;
}

inline bool CharCodeValue(const std::string& token, int& value) {
    if (token.empty()) return false;
    const bool hex = token.size() > 2 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X');
    const char* const digits = hex ? token.c_str() + 2 : token.c_str();
    char* stop = nullptr;
    const long parsed = std::strtol(digits, &stop, hex ? 16 : 10);
    if (stop == digits) return false;
    if (*stop == '.') {
        for (const char* fraction = stop + 1; *fraction != '\0'; ++fraction) {
            if (*fraction != '0') return false;
        }
    }
    else if (*stop != '\0') {
        return false;
    }
    if (parsed < 0 || parsed > 0x10FFFF) return false;
    value = static_cast<int>(parsed);
    return true;
}

inline bool FoldStringChar(const std::string& in, std::string& out) {
    if (in.find("string.char") == std::string::npos) return false;
    // An alternation here would multiply the NFA states per repeat; libstdc++ gives up near 4000.
    static const std::regex pattern(
        R"(string\.char\s*\(\s*([0-9A-Fa-fXx.]{1,12}(?:\s*,\s*[0-9A-Fa-fXx.]{1,12}){0,1000})\s*\))");
    static const std::regex number(R"([0-9A-Fa-fXx.]{1,12})");

    return ReplaceEach(in, pattern, [](const std::smatch& match, std::string& replacement) {
        const std::string args = match.str(1);
        std::string decoded = "\"";
        for (auto it = std::sregex_iterator(args.begin(), args.end(), number); it != std::sregex_iterator(); ++it) {
            int value = 0;
            if (!CharCodeValue(it->str(), value)) return false;
            if (!IsFoldableChar(value)) return false;
            decoded += static_cast<char>(value);
        }
        decoded += '"';
        replacement = decoded + NewlinesIn(match.str(0));
        return true;
    }, out);
}

inline bool FoldEscapes(const std::string& in, std::string& out) {
    if (in.find('\\') == std::string::npos) return false;
    static const std::regex pattern(R"(\\x([0-9a-fA-F]{2})|\\u\{([0-9a-fA-F]{1,6})\}|\\(\d{1,3}))");

    return ReplaceEach(in, pattern, [](const std::smatch& match, std::string& replacement) {
        int value = 0;
        if (match[1].matched) value = static_cast<int>(std::strtol(match.str(1).c_str(), nullptr, 16));
        else if (match[2].matched) value = static_cast<int>(std::strtol(match.str(2).c_str(), nullptr, 16));
        else value = std::atoi(match.str(3).c_str());
        if (!IsFoldableChar(value)) return false;
        replacement = std::string(1, static_cast<char>(value));
        return true;
    }, out);
}

inline bool FoldTableConcat(const std::string& in, std::string& out) {
    if (in.find("table.concat") == std::string::npos) return false;
    static const std::regex pattern(
        R"(table\.concat\s*\(\s*\{\s*)"
        R"(((?:["'][^"'\\\r\n]{0,200}["'])(?:\s*,\s*["'][^"'\\\r\n]{0,200}["']){0,200}))"
        R"(\s*,?\s*\}\s*(?:,\s*(["'][^"'\\\r\n]{0,8}["'])\s*)?\))");
    static const std::regex element(R"(["']([^"'\\\r\n]{0,200})["'])");

    return ReplaceEach(in, pattern, [](const std::smatch& match, std::string& replacement) {
        std::string separator;
        if (match[2].matched) {
            const std::string raw = match.str(2);
            if (raw.size() >= 2) separator = raw.substr(1, raw.size() - 2);
        }
        const std::string list = match.str(1);
        std::string joined;
        bool first = true;
        for (auto it = std::sregex_iterator(list.begin(), list.end(), element);
             it != std::sregex_iterator(); ++it) {
            if (!first) joined += separator;
            joined += it->str(1);
            first = false;
        }
        if (first) return false;
        replacement = "\"" + joined + "\"" + NewlinesIn(match.str(0));
        return true;
    }, out);
}

inline bool FoldReverse(const std::string& in, std::string& out) {
    if (in.find("reverse") == std::string::npos) return false;
    static const std::regex pattern(
        R"(\(\s*(["'])([^"'\\\r\n]{0,400})\1\s*\)\s*:\s*reverse\s*\(\s*\))"
        R"(|string\.reverse\s*\(\s*(["'])([^"'\\\r\n]{0,400})\3\s*\))");

    return ReplaceEach(in, pattern, [](const std::smatch& match, std::string& replacement) {
        std::string value = match[2].matched ? match.str(2) : match.str(4);
        std::reverse(value.begin(), value.end());
        replacement = "\"" + value + "\"" + NewlinesIn(match.str(0));
        return true;
    }, out);
}

// Folding runs over the whole file, so unbounded repeats here overflow the stack.

inline bool FoldConcatenations(const std::string& in, std::string& out) {
    if (in.find("..") == std::string::npos) return false;
    static const std::regex pattern(R"((["'])([^"'\\\r\n]{0,400})\1\s*\.\.\s*(["'])([^"'\\\r\n]{0,400})\3)");

    return ReplaceEach(in, pattern, [](const std::smatch& match, std::string& replacement) {
        replacement = "\"" + match.str(2) + match.str(4) + "\"" + NewlinesIn(match.str(0));
        return true;
    }, out);
}

inline size_t EndOfShortString(const std::string& text, size_t quote) {
    const char delimiter = text[quote];
    for (size_t i = quote + 1; i < text.size(); ++i) {
        if (text[i] == '\\') { i++; continue; }
        if (text[i] == '\r' || text[i] == '\n') return std::string::npos;
        if (text[i] == delimiter) return i;
    }
    return std::string::npos;
}

inline size_t LongBracketLevel(const std::string& text, size_t open) {
    if (text[open] != '[') return std::string::npos;
    size_t i = open + 1;
    while (i < text.size() && text[i] == '=') i++;
    if (i >= text.size() || text[i] != '[') return std::string::npos;
    return i - open - 1;
}

inline size_t EndOfLongBracket(const std::string& text, size_t open, size_t level) {
    const std::string closing = "]" + std::string(level, '=') + "]";
    const size_t at = text.find(closing, open + level + 2);
    return at == std::string::npos ? std::string::npos : at + closing.size() - 1;
}

inline bool FoldParenFreeCalls(const std::string& content, std::string& out) {
    out.clear();
    out.reserve(content.size() + 16);
    bool changed = false;

    for (size_t i = 0; i < content.size(); ++i) {
        const char c = content[i];

        if (c == '"' || c == '\'') {
            const size_t end = EndOfShortString(content, i);
            if (end == std::string::npos) { out += c; continue; }
            out.append(content, i, end - i + 1);
            i = end;
            continue;
        }

        const size_t level = c == '[' ? LongBracketLevel(content, i) : std::string::npos;
        if (level != std::string::npos) {
            const size_t end = EndOfLongBracket(content, i, level);
            if (end == std::string::npos) { out += c; continue; }
            out.append(content, i, end - i + 1);
            i = end;
            continue;
        }

        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_')) { out += c; continue; }

        size_t nameEnd = i;
        while (nameEnd + 1 < content.size() &&
               (std::isalnum(static_cast<unsigned char>(content[nameEnd + 1])) ||
                content[nameEnd + 1] == '_')) {
            nameEnd++;
        }

        size_t after = nameEnd + 1;
        while (after < content.size() && (content[after] == ' ' || content[after] == '\t')) after++;

        bool wrapped = false;
        if (after < content.size() && content[after] == '(') {
            size_t inner = after + 1;
            while (inner < content.size() && (content[inner] == ' ' || content[inner] == '\t')) inner++;
            if (inner < content.size() && content[inner] == '[') {
                after = inner;
                wrapped = true;
            }
        }

        size_t argEnd = std::string::npos;
        size_t bodyAt = 0;
        size_t bodyLength = 0;
        bool longBracket = false;
        if (after < content.size() && (content[after] == '"' || content[after] == '\'')) {
            argEnd = EndOfShortString(content, after);
        }
        else if (after < content.size() && content[after] == '[') {
            const size_t argLevel = LongBracketLevel(content, after);
            if (argLevel != std::string::npos) {
                argEnd = EndOfLongBracket(content, after, argLevel);
                if (argEnd != std::string::npos) {
                    longBracket = true;
                    bodyAt = after + argLevel + 2;
                    bodyLength = argEnd - argLevel - 1 - bodyAt;
                }
            }
        }

        size_t consumed = argEnd;
        if (wrapped && argEnd != std::string::npos) {
            size_t close = argEnd + 1;
            while (close < content.size() && (content[close] == ' ' || content[close] == '\t')) close++;
            if (close < content.size() && content[close] == ')') consumed = close;
            else argEnd = std::string::npos;
        }

        out.append(content, i, nameEnd - i + 1);
        if (argEnd == std::string::npos) { i = nameEnd; continue; }

        const bool quotable = longBracket &&
            content.find_first_of("\"'\\\r\n", bodyAt) >= bodyAt + bodyLength;

        out += '(';
        if (quotable) {
            out += '"';
            out.append(content, bodyAt, bodyLength);
            out += '"';
        }
        else {
            out.append(content, after, argEnd - after + 1);
        }
        out += ')';
        changed = true;
        i = consumed;
    }

    return changed;
}

inline bool FoldLiterals(const std::string& content, std::string& folded, int maxPasses = 12) {
    const std::string* current = &content;
    std::string scratch;
    bool changedAny = false;

    for (int pass = 0; pass < maxPasses; ++pass) {
        bool changed = false;
        if (FoldStringChar(*current, scratch)) { folded.swap(scratch); current = &folded; changed = true; }
        if (FoldEscapes(*current, scratch)) { folded.swap(scratch); current = &folded; changed = true; }
        if (FoldReverse(*current, scratch)) { folded.swap(scratch); current = &folded; changed = true; }
        if (FoldTableConcat(*current, scratch)) { folded.swap(scratch); current = &folded; changed = true; }
        if (FoldConcatenations(*current, scratch)) { folded.swap(scratch); current = &folded; changed = true; }
        if (!changed) break;
        changedAny = true;
    }
    return changedAny;
}

inline std::string FoldLiterals(const std::string& content) {
    std::string folded;
    return FoldLiterals(content, folded) ? folded : content;
}

class LineIndex {
public:
    explicit LineIndex(const std::string& content) {
        m_starts.push_back(0);
        for (size_t i = 0; i < content.size(); ++i) {
            if (content[i] == '\r') {
                if (i + 1 < content.size() && content[i + 1] == '\n') ++i;
                m_starts.push_back(i + 1);
            }
            else if (content[i] == '\n') {
                m_starts.push_back(i + 1);
            }
        }
    }

    int LineFor(size_t offset) const {
        const auto it = std::upper_bound(m_starts.begin(), m_starts.end(), offset);
        return static_cast<int>(it - m_starts.begin());
    }

    size_t LineCount(const std::string& content) const {
        if (m_starts.size() > 1 && m_starts.back() >= content.size()) return m_starts.size() - 1;
        return m_starts.size();
    }

    std::string TextOf(const std::string& content, int lineNumber) const {
        if (lineNumber < 1 || static_cast<size_t>(lineNumber) > m_starts.size()) return "";

        const size_t start = m_starts[static_cast<size_t>(lineNumber) - 1];
        if (start >= content.size()) return "";

        size_t end = content.find_first_of("\r\n", start);
        if (end == std::string::npos) end = content.size();

        return content.substr(start, end - start);
    }

private:
    std::vector<size_t> m_starts;
};

using DetectionSink = std::function<void(const Detection&)>;
using PatternProblemSink = std::function<void(const std::string& patternId, const std::string& detail)>;

class Scanner {
public:
    static constexpr size_t kWindowSize = 65536;
    static constexpr size_t kWindowOverlap = 8192;
    static constexpr int kContextLines = 3;
    static constexpr size_t kContextLineLength = 160;

    explicit Scanner(const PatternSet& patterns) : m_patterns(&patterns) {}

    void SetExcludedTags(std::set<std::string> tags) { m_excludedTags = std::move(tags); }
    void SetPrefilterEnabled(bool enabled) { m_prefilter = enabled; }

    void Scan(const std::string& content,
              const std::string& filePath,
              const std::string& extension,
              const DetectionSink& sink,
              const PatternProblemSink& onProblem = nullptr) const {
        const std::vector<Pattern>* all = m_patterns->ForExtension(extension);
        if (all == nullptr || content.empty()) return;

        std::vector<const Pattern*> patterns;
        patterns.reserve(all->size());
        for (const Pattern& pattern : *all) {
            if (!pattern.AppliesTo(filePath)) continue;
            if (!m_excludedTags.empty()) {
                bool excluded = false;
                for (const std::string& tag : pattern.tags) {
                    if (m_excludedTags.count(tag) > 0) { excluded = true; break; }
                }
                if (excluded) continue;
            }
            patterns.push_back(&pattern);
        }
        if (patterns.empty()) return;

        const LineIndex rawIndex(content);
        std::set<std::pair<int, size_t>> seen;

        const AhoCorasick* automaton =
            (m_prefilter && m_patterns->Automaton().Built()) ? &m_patterns->Automaton() : nullptr;

        const std::string stripped = (extension == ".lua") ? StripLuaComments(content) : content;

        std::string called;
        const bool normalised = extension == ".lua" && FoldParenFreeCalls(stripped, called);
        const std::string& base = normalised ? called : stripped;
        if (normalised) {
            const LineIndex calledIndex(base);
            ScanText(base, calledIndex, content, rawIndex, false, patterns, filePath, seen, sink,
                     onProblem, automaton);
        }
        else {
            ScanText(base, rawIndex, content, rawIndex, false, patterns, filePath, seen, sink,
                     onProblem, automaton);
        }

        std::string folded;
        if (FoldLiterals(base, folded)) {
            const LineIndex foldedIndex(folded);
            ScanText(folded, foldedIndex, content, rawIndex, true, patterns, filePath, seen, sink, onProblem, automaton);
        }
    }

private:
    static void ScanText(const std::string& text, const LineIndex& textIndex,
                         const std::string& raw, const LineIndex& rawIndex,
                         bool isFolded,
                         const std::vector<const Pattern*>& patterns,
                         const std::string& filePath,
                         std::set<std::pair<int, size_t>>& seen,
                         const DetectionSink& sink,
                         const PatternProblemSink& onProblem,
                         const AhoCorasick* automaton) {
        std::vector<bool> present;

        const size_t stride = kWindowSize - kWindowOverlap;
        for (size_t start = 0; start < text.size(); start += stride) {
            const size_t end = std::min(start + kWindowSize, text.size());

            if (automaton != nullptr) {
                automaton->Search(text.data() + start, end - start, present);
            }

            for (size_t p = 0; p < patterns.size(); ++p) {
                const Pattern& pattern = *patterns[p];

                if (automaton != nullptr && !pattern.requiredLiterals.empty()) {
                    bool possible = false;
                    for (size_t literal : pattern.requiredLiterals) {
                        if (literal < present.size() && present[literal]) { possible = true; break; }
                    }
                    if (!possible) continue;
                }

                try {
                auto it = std::sregex_iterator(text.begin() + static_cast<std::ptrdiff_t>(start),
                                               text.begin() + static_cast<std::ptrdiff_t>(end),
                                               pattern.regex,
                                               start == 0
                                                   ? std::regex_constants::match_default
                                                   : std::regex_constants::match_prev_avail);
                const auto last = std::sregex_iterator();

                for (; it != last; ++it) {
                    const std::smatch& match = *it;
                    const size_t offset = start + static_cast<size_t>(match.position(0));
                    const int lineNumber = textIndex.LineFor(offset);

                    if (!seen.insert({ lineNumber, p }).second) continue;

                    Detection detection;
                    detection.file = filePath;
                    detection.detection = pattern.definition;
                    detection.severity = pattern.severity;
                    detection.id = pattern.id;
                    detection.hint = pattern.hint;
                    detection.lineNumber = lineNumber;
                    detection.lineText = sanitizeForReport(trimExtraWhiteSpaces(rawIndex.TextOf(raw, lineNumber)));
                    detection.decodedContent = Enrich(pattern, match.str(0));
                    CollectContext(raw, rawIndex, lineNumber, detection);

                    if (detection.decodedContent.empty() && isFolded) {
                        const std::string foldedLine = trimExtraWhiteSpaces(textIndex.TextOf(text, lineNumber));
                        const std::string rawLine = trimExtraWhiteSpaces(rawIndex.TextOf(raw, lineNumber));
                        if (foldedLine != rawLine) {
                            detection.decodedContent = sanitizeForReport(foldedLine, 200);
                        }
                    }

                    sink(detection);
                }
                }
                catch (const std::regex_error& e) {
                    if (onProblem) {
                        onProblem(pattern.id.empty() ? pattern.definition : pattern.id, e.what());
                    }
                }
            }

            if (end == text.size()) break;
        }
    }

    static void CollectContext(const std::string& raw, const LineIndex& rawIndex,
                               int lineNumber, Detection& detection) {
        if (lineNumber < 1) return;

        const int first = std::max(1, lineNumber - kContextLines);
        detection.contextStart = first;
        const int last = std::min(lineNumber + kContextLines,
                                  static_cast<int>(rawIndex.LineCount(raw)));
        for (int line = first; line <= last; ++line) {
            detection.context.push_back(
                sanitizeForReport(rawIndex.TextOf(raw, line), kContextLineLength));
        }
    }

    static std::string Enrich(const Pattern& pattern, const std::string& matchText) {
        if (pattern.definition.find("CharCode") != std::string::npos ||
            pattern.definition.find("Obfuscation") != std::string::npos) {
            return sanitizeForReport(DecodeCharCodes(matchText), 200);
        }
        if (pattern.definition.find("Base64") != std::string::npos) {
            return sanitizeForReport(DecodePrintableBase64(matchText), 200);
        }
        return "";
    }

    static std::string DecodeCharCodes(const std::string& text) {
        static const std::regex numberRegex(R"(\d{1,9})");

        std::string decoded;
        for (auto it = std::sregex_iterator(text.begin(), text.end(), numberRegex);
             it != std::sregex_iterator(); ++it) {
            const int value = std::atoi(it->str().c_str());
            if (value >= 32 && value <= 126) decoded += static_cast<char>(value);
            else if (value == 9 || value == 10 || value == 13) decoded += ' ';
        }
        return decoded;
    }

    static std::string DecodePrintableBase64(const std::string& text) {
        static const std::regex base64Regex(R"([A-Za-z0-9+/]{40,}={0,2})");

        std::smatch match;
        if (!std::regex_search(text, match, base64Regex)) return "";

        const std::string decoded = DecodeBase64(match.str());
        if (decoded.length() <= 5) return "";

        const size_t inspect = std::min(decoded.length(), static_cast<size_t>(50));
        for (size_t i = 0; i < inspect; ++i) {
            const unsigned char c = static_cast<unsigned char>(decoded[i]);
            if (c < 32 && c != '\n' && c != '\r' && c != '\t') return "";
        }
        return decoded;
    }

    const PatternSet* m_patterns;
    std::set<std::string> m_excludedTags;
    bool m_prefilter = true;
};
