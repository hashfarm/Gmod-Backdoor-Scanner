#pragma once
#include <string>
#include <algorithm>
#include <cctype>

inline std::string trimExtraWhiteSpaces(const std::string& str) {
    std::string result = str;
    result.erase(std::unique(result.begin(), result.end(), [](char a, char b) {
        return std::isspace(static_cast<unsigned char>(a)) && std::isspace(static_cast<unsigned char>(b));
        }), result.end());

    const size_t first = result.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const size_t last = result.find_last_not_of(" \t\r\n");
    return result.substr(first, last - first + 1);
}

inline std::string SanitizeUtf8(const std::string& str) {
    std::string result;
    result.reserve(str.size());

    size_t i = 0;
    while (i < str.size()) {
        const unsigned char lead = static_cast<unsigned char>(str[i]);
        if (lead < 0x20 || lead == 0x7f) { result += '?'; i++; continue; }
        if (lead < 0x80) { result += str[i]; i++; continue; }

        size_t length = 0;
        unsigned int code = 0;
        if ((lead & 0xe0) == 0xc0) { length = 2; code = lead & 0x1fu; }
        else if ((lead & 0xf0) == 0xe0) { length = 3; code = lead & 0x0fu; }
        else if ((lead & 0xf8) == 0xf0) { length = 4; code = lead & 0x07u; }
        else { result += '?'; i++; continue; }

        if (i + length > str.size()) { result += '?'; i++; continue; }

        bool valid = true;
        for (size_t j = 1; j < length; ++j) {
            const unsigned char next = static_cast<unsigned char>(str[i + j]);
            if ((next & 0xc0) != 0x80) { valid = false; break; }
            code = (code << 6) | (next & 0x3fu);
        }
        if (!valid) { result += '?'; i++; continue; }

        const bool overlong = (length == 2 && code < 0x80) ||
                              (length == 3 && code < 0x800) ||
                              (length == 4 && code < 0x10000);
        const bool surrogate = code >= 0xd800 && code <= 0xdfff;
        if (overlong || surrogate || code > 0x10ffff) {
            result += '?';
            i++;
            continue;
        }

        result.append(str, i, length);
        i += length;
    }
    return result;
}

inline std::string sanitizeForReport(const std::string& str, size_t maxLength = 512) {
    std::string result;
    result.reserve(std::min(str.size(), maxLength));

    for (char raw : str) {
        if (result.size() >= maxLength) {
            result += "...";
            break;
        }
        const unsigned char c = static_cast<unsigned char>(raw);
        if (c == '\t') result += ' ';
        else if (c < 0x20 || c >= 0x7f) result += '.';
        else result += raw;
    }
    return result;
}
