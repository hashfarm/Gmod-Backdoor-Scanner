#pragma once
#include <string>
#include <algorithm>

std::string toRawString(const std::string& in) {
    std::string ret = in;
    size_t pos = 0;
    while ((pos = ret.find('\t', pos)) != std::string::npos) {
        ret.replace(pos, 1, "\\t");
        pos += 2;
    }
    return ret;
}

std::string trimExtraWhiteSpaces(const std::string& str) {
    std::string result = str;
    result.erase(std::unique(result.begin(), result.end(), [](char a, char b) {
        return std::isspace(a) && std::isspace(b);
        }), result.end());
    return result;
}