#pragma once
#include <string>

std::string toRawString(const std::string & in)
{
    std::string ret = in;
    auto p = ret.find('\t');
    if (p != ret.npos)
    {
        ret.replace(p, 1, "\\t");
    }

    return ret;
}

std::string trimExtraWhiteSpaces(const std::string& str) {
    std::string NotConst = str;
    std::string s;
    bool first = true;
    bool space = false;
    std::string::iterator iter;
    for (iter = NotConst.begin(); iter != NotConst.end(); ++iter) {
        if (*iter == ' ') {
            if (first == false) {
                space = true;
            }
        }
        else {
            if (*iter != ',' && *iter != '.') {
                if (space) {
                    s.push_back(' ');
                }
            }
            s.push_back(*iter);
            space = false;
            first = false;
        }
    }
    return s;
}
