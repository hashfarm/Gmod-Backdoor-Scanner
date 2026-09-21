#pragma once
#include <cstddef>
#include <string>

namespace binstr {

constexpr size_t kMinimumRun = 6;
constexpr size_t kMaximumOutput = 4 * 1024 * 1024;

inline bool IsPrintableRunChar(unsigned char value) {
    return value >= 0x20 && value < 0x7f;
}

inline std::string ExtractPrintableRuns(const std::string& content, size_t minimumRun = kMinimumRun,
                                        size_t limit = kMaximumOutput, bool* truncated = nullptr) {
    std::string out;
    std::string run;
    run.reserve(128);
    bool cut = false;

    auto flush = [&]() {
        if (run.size() >= minimumRun) {
            if (out.size() + run.size() + 1 <= limit) {
                out += run;
                out += '\n';
            }
            else {
                const size_t room = out.size() + 1 < limit ? limit - out.size() - 1 : 0;
                if (room >= minimumRun) {
                    out.append(run, 0, room);
                    out += '\n';
                }
                cut = true;
            }
        }
        run.clear();
    };

    size_t i = 0;
    bool wideRun = false;
    for (; i < content.size() && out.size() < limit; ++i) {
        const unsigned char value = static_cast<unsigned char>(content[i]);
        if (IsPrintableRunChar(value)) {
            run += content[i];
            continue;
        }
        if (value == 0 && i + 1 < content.size()) {
            const unsigned char next = static_cast<unsigned char>(content[i + 1]);
            if (!run.empty() && IsPrintableRunChar(next)) {
                const bool wideText = wideRun || i + 2 >= content.size() ||
                                      static_cast<unsigned char>(content[i + 2]) == 0;
                if (wideText) { wideRun = true; continue; }
            }
        }
        wideRun = false;
        flush();
    }
    flush();
    if (i < content.size()) cut = true;
    if (truncated != nullptr) *truncated = cut;
    return out;
}

}
