#pragma once
#include <cmath>
#include <cstdint>
#include <functional>
#include <set>
#include <string>
#include <vector>

#include "CleanString.h"
#include "Scanner.h"

struct StructuralSignal {
    const char* id;
    const char* severity;
    const char* title;
    const char* hint;
};

inline const std::vector<StructuralSignal>& StructuralSignals() {
    static const std::vector<StructuralSignal> signals = {
        { "OBF-001", "high", "Packed Source Line",
          "A single line of several thousand characters with almost no spaces in it. Lua written "
          "to be read does not look like this; a packer or a minifier produced it. Nothing here "
          "says what the line does, which is the reason it was packed." },
        { "OBF-002", "high", "Escape-Dominated Content",
          "Hundreds of numeric or hex escapes. Individually each is a character; together they are "
          "a program written so that no readable word survives. Decode the run before judging it." },
        { "OBF-003", "medium", "Whitespace-Free Source",
          "A file of real size with almost no whitespace. Stripping layout is the cheapest way to "
          "make code unreadable while keeping it valid." },
        { "OBF-004", "high", "Look-Alike Identifier Names",
          "Several identifiers built only from characters that look alike in most fonts, such as "
          "l, I, 1, O and 0. This is a deliberate technique for making code impossible to follow "
          "by eye; no human names variables this way." },
        { "OBF-005", "medium", "High Byte Entropy",
          "The byte distribution is closer to encoded data than to source code. Something in this "
          "file is a blob rather than something anyone wrote. Text in a non-Latin script raises "
          "entropy for an honest reason and is not measured, so a match here is Latin-alphabet "
          "source that does not read like source." },
        { "OBF-006", "high", "Invisible Characters In Source",
          "Characters that render as nothing, or that reorder what is displayed, used inside the "
          "source itself. Every identifier can be a different run of them while the file looks "
          "blank in an editor, and direction marks can make a line read in an order it does not "
          "execute in. No compiler, formatter or honest author puts these in Lua." },
    };
    return signals;
}

inline StructuralSignal StructuralSignalById(const std::string& id) {
    for (const StructuralSignal& signal : StructuralSignals()) {
        if (id == signal.id) return signal;
    }
    return StructuralSignals().front();
}

inline bool IsStructuralSignalId(const std::string& id) {
    for (const StructuralSignal& signal : StructuralSignals()) {
        if (id == signal.id) return true;
    }
    return false;
}

namespace heuristics {

constexpr size_t kPackedLineLength = 3000;
constexpr double kPackedLineSpaceRatio = 0.15;
constexpr size_t kEscapeRunCount = 200;
constexpr size_t kDenseMinimumBytes = 1000;
constexpr double kDenseWhitespaceRatio = 0.04;
constexpr size_t kLookAlikeNameCount = 5;
constexpr size_t kLookAlikeNameLength = 6;
constexpr size_t kEntropyMinimumBytes = 2048;
constexpr double kEntropyBitsPerByte = 5.7;
constexpr double kEntropyTextNonAsciiShare = 0.10;

inline double ShannonEntropy(const std::string& content) {
    if (content.empty()) return 0.0;

    size_t counts[256] = {};
    for (char raw : content) counts[static_cast<unsigned char>(raw)]++;

    const double total = static_cast<double>(content.size());
    double bits = 0.0;
    for (size_t count : counts) {
        if (count == 0) continue;
        const double probability = static_cast<double>(count) / total;
        bits -= probability * std::log2(probability);
    }
    return bits;
}

constexpr size_t kInvisibleCharCount = 8;

inline bool IsInvisibleCodePoint(uint32_t code) {
    if (code == 0x00ad || code == 0x180e) return true;
    if (code == 0x200b) return true;
    if (code >= 0x202a && code <= 0x202e) return true;
    if (code == 0x2060 || code == 0x2061 || code == 0x2062 || code == 0x2063 || code == 0x2064) return true;
    if (code >= 0x2066 && code <= 0x206f) return true;
    if (code == 0xfeff) return true;
    if (code >= 0xfff9 && code <= 0xfffb) return true;
    if (code >= 0x1d173 && code <= 0x1d17a) return true;
    if (code >= 0xe0000 && code <= 0xe007f) return true;
    return false;
}

inline bool DecodeUtf8(const std::string& content, size_t& i, uint32_t& code) {
    const unsigned char lead = static_cast<unsigned char>(content[i]);
    size_t length = 0;
    if (lead < 0x80) { code = lead; i++; return true; }
    if ((lead & 0xe0) == 0xc0) { length = 2; code = lead & 0x1fu; }
    else if ((lead & 0xf0) == 0xe0) { length = 3; code = lead & 0x0fu; }
    else if ((lead & 0xf8) == 0xf0) { length = 4; code = lead & 0x07u; }
    else return false;

    if (i + length > content.size()) return false;
    for (size_t j = 1; j < length; ++j) {
        const unsigned char next = static_cast<unsigned char>(content[i + j]);
        if ((next & 0xc0) != 0x80) return false;
        code = (code << 6) | (next & 0x3fu);
    }
    i += length;
    return true;
}

inline size_t CountInvisibleCharacters(const std::string& content) {
    size_t found = 0;
    size_t i = 0;
    while (i < content.size()) {
        const size_t start = i;
        uint32_t code = 0;
        if (!DecodeUtf8(content, i, code)) { i = start + 1; continue; }
        if (start == 0 && code == 0xfeff) continue;
        if (IsInvisibleCodePoint(code)) found++;
    }
    return found;
}

inline bool LooksLikeNonLatinText(const std::string& content) {
    if (content.empty()) return false;
    size_t textBytes = 0;
    size_t i = 0;
    while (i < content.size()) {
        const size_t start = i;
        uint32_t code = 0;
        if (!DecodeUtf8(content, i, code)) return false;
        if (code < 0x80 || IsInvisibleCodePoint(code)) continue;
        textBytes += i - start;
    }
    return static_cast<double>(textBytes) / static_cast<double>(content.size()) >=
           kEntropyTextNonAsciiShare;
}

inline bool IsLookAlikeName(const std::string& name) {
    if (name.size() < kLookAlikeNameLength) return false;
    bool hasLetter = false;
    for (char c : name) {
        if (c == 'l' || c == 'I' || c == 'O') hasLetter = true;
        else if (c != '1' && c != '0' && c != '_') return false;
    }
    return hasLetter;
}

}

inline void CollectStructuralSignals(const std::string& content, const std::string& extension,
                                     const std::function<void(const Detection&)>& sink) {
    if (extension != ".lua") return;

    auto emit = [&](const char* id, int lineNumber, const std::string& lineText) {
        const StructuralSignal signal = StructuralSignalById(id);
        Detection detection;
        detection.detection = std::string("[") + ToUpperAscii(signal.severity) + "] " +
                              signal.id + " " + signal.title;
        detection.severity = signal.severity;
        detection.id = signal.id;
        detection.hint = signal.hint;
        detection.lineNumber = lineNumber;
        detection.lineText = sanitizeForReport(lineText, 200);
        sink(detection);
    };

    int lineNumber = 0;
    size_t lineStart = 0;
    size_t whitespace = 0;
    bool packedReported = false;

    for (size_t i = 0; i <= content.size(); ++i) {
        const bool end = (i == content.size());
        if (!end) {
            const char c = content[i];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') whitespace++;
            if (c != '\n' && c != '\r') continue;
            if (c == '\r' && i + 1 < content.size() && content[i + 1] == '\n') continue;
        }
        lineNumber++;
        if (!packedReported) {
            const size_t length = i - lineStart;
            if (length >= heuristics::kPackedLineLength) {
                size_t spaces = 0;
                for (size_t j = lineStart; j < i; ++j) {
                    if (content[j] == ' ' || content[j] == '\t') spaces++;
                }
                if (static_cast<double>(spaces) / static_cast<double>(length) <
                    heuristics::kPackedLineSpaceRatio) {
                    emit("OBF-001", lineNumber, content.substr(lineStart, 200));
                    packedReported = true;
                }
            }
        }
        lineStart = i + 1;
        if (end) break;
    }

    {
        size_t escapes = 0;
        int escapeLine = 1;
        int currentLine = 1;
        bool haveLine = false;
        for (size_t i = 0; i + 1 < content.size(); ++i) {
            if (content[i] == '\n') { currentLine++; continue; }
            if (content[i] != '\\') continue;
            const char next = content[i + 1];
            const bool hex = (next == 'x' || next == 'X');
            const bool digit = next >= '0' && next <= '9';
            if (!hex && !digit) continue;
            escapes++;
            if (!haveLine) { escapeLine = currentLine; haveLine = true; }
        }
        if (escapes >= heuristics::kEscapeRunCount) emit("OBF-002", escapeLine, "");
    }

    if (content.size() >= heuristics::kDenseMinimumBytes) {
        const double ratio = static_cast<double>(whitespace) / static_cast<double>(content.size());
        if (ratio < heuristics::kDenseWhitespaceRatio) emit("OBF-003", 0, "");
    }

    {
        std::set<std::string> names;
        std::string current;
        for (size_t i = 0; i <= content.size(); ++i) {
            const char c = i < content.size() ? content[i] : ' ';
            const bool wordChar = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                  (c >= '0' && c <= '9') || c == '_';
            if (wordChar) { current += c; continue; }
            if (heuristics::IsLookAlikeName(current)) names.insert(current);
            current.clear();
        }
        if (names.size() >= heuristics::kLookAlikeNameCount) emit("OBF-004", 0, "");
    }

    if (content.size() >= heuristics::kEntropyMinimumBytes &&
        !heuristics::LooksLikeNonLatinText(content) &&
        heuristics::ShannonEntropy(content) >= heuristics::kEntropyBitsPerByte) {
        emit("OBF-005", 0, "");
    }

    if (heuristics::CountInvisibleCharacters(content) >= heuristics::kInvisibleCharCount) {
        emit("OBF-006", 0, "");
    }
}
