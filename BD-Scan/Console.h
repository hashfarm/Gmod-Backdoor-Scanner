#pragma once
#include <cctype>
#include <cstdlib>
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif

namespace con {

enum class Mode { Auto, Always, Never };

inline bool& ColourState() {
    static bool enabled = false;
    return enabled;
}

inline std::string EnvValue(const char* name) {
#ifdef _WIN32
    char buffer[256];
    const DWORD size = GetEnvironmentVariableA(name, buffer, static_cast<DWORD>(sizeof(buffer)));
    if (size == 0 || size >= sizeof(buffer)) return std::string();
    return std::string(buffer, size);
#else
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
#endif
}

inline bool StdoutIsTerminal() {
#ifdef _WIN32
    return _isatty(_fileno(stdout)) != 0;
#else
    return isatty(STDOUT_FILENO) != 0;
#endif
}

inline bool EnableVirtualTerminal() {
#ifdef _WIN32
    const HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (handle == INVALID_HANDLE_VALUE) return false;
    DWORD mode = 0;
    if (!GetConsoleMode(handle, &mode)) return false;
    if (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) return true;
    return SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
#else
    return true;
#endif
}

inline void Configure(Mode mode) {
    if (mode == Mode::Never) {
        ColourState() = false;
        return;
    }
    if (mode == Mode::Always) {
        EnableVirtualTerminal();
        ColourState() = true;
        return;
    }

    if (!EnvValue("NO_COLOR").empty()) {
        ColourState() = false;
        return;
    }
    if (EnvValue("TERM") == "dumb") {
        ColourState() = false;
        return;
    }
    ColourState() = StdoutIsTerminal() && EnableVirtualTerminal();
}

inline bool Enabled() { return ColourState(); }

inline std::string Wrap(const char* codes, const std::string& text) {
    if (!Enabled()) return text;
    return std::string("\033[") + codes + "m" + text + "\033[0m";
}

inline std::string Bold(const std::string& text) { return Wrap("1", text); }
inline std::string Dim(const std::string& text) { return Wrap("2", text); }
inline std::string Underline(const std::string& text) { return Wrap("4", text); }

inline std::string Red(const std::string& text) { return Wrap("38;5;203", text); }
inline std::string Orange(const std::string& text) { return Wrap("38;5;214", text); }
inline std::string Yellow(const std::string& text) { return Wrap("38;5;179", text); }
inline std::string Grey(const std::string& text) { return Wrap("38;5;245", text); }
inline std::string Blue(const std::string& text) { return Wrap("38;5;110", text); }
inline std::string Green(const std::string& text) { return Wrap("38;5;114", text); }

inline const char* SeverityCodes(const std::string& severity) {
    if (severity == "critical") return "1;97;48;5;160";
    if (severity == "high") return "1;16;48;5;214";
    if (severity == "medium") return "1;16;48;5;179";
    return "1;16;48;5;248";
}

inline std::string SeverityText(const std::string& severity, const std::string& text) {
    if (severity == "critical") return Red(text);
    if (severity == "high") return Orange(text);
    if (severity == "medium") return Yellow(text);
    return Grey(text);
}

inline std::string Badge(const std::string& severity) {
    std::string label = severity;
    if (!label.empty()) label[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(label[0])));
    while (label.size() < 8) label += ' ';
    if (!Enabled()) return "[" + label + "]";
    return std::string("\033[") + SeverityCodes(severity) + "m " + label + " \033[0m";
}

inline std::string Bar(const std::string& severity, int count, int width) {
    if (count <= 0 || width <= 0) return "";
    std::string block;
    if (!Enabled()) {
        for (int i = 0; i < width; ++i) block += "=";
        return block;
    }
    for (int i = 0; i < width; ++i) block += "\xe2\x96\x88";
    return std::string("\033[") + "38;5;" +
           (severity == "critical" ? "160" : severity == "high" ? "214" : severity == "medium" ? "179" : "248") +
           "m" + block + "\033[0m";
}

inline std::string Rule(size_t width) {
    std::string line;
    for (size_t i = 0; i < width; ++i) line += "-";
    return Grey(line);
}

}
