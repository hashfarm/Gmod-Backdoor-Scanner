#include "GMAReader.h"
#include "CleanString.h"

#include <cstddef>
#include <cstdint>
#include <cctype>
#include <string>

static bool IsValidUtf8(const std::string& value) {
    return SanitizeUtf8(value) == value;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 1 << 16) return 0;

    const std::string raw(reinterpret_cast<const char*>(data), size);

    bool altered = false;
    const std::string safe = GMAReader::SanitizeEntryName(raw, altered);

    if (safe.empty()) __builtin_trap();
    if (!IsValidUtf8(safe)) __builtin_trap();

    for (char c : safe) {
        const unsigned char value = static_cast<unsigned char>(c);
        if (value < 0x20 || value == 0x7f) __builtin_trap();
        if (c == '\\') __builtin_trap();
    }

    if (safe.front() == '/') __builtin_trap();
    if (safe.find("/../") != std::string::npos) __builtin_trap();
    if (safe.rfind("../", 0) == 0) __builtin_trap();
    if (safe.size() >= 3 && safe.compare(safe.size() - 3, 3, "/..") == 0) __builtin_trap();
    if (safe.size() >= 2 && safe[1] == ':' &&
        std::isalpha(static_cast<unsigned char>(safe[0]))) {
        __builtin_trap();
    }
    if (safe.find("//") != std::string::npos) __builtin_trap();

    if (!altered && safe != raw) __builtin_trap();

    bool again = false;
    if (GMAReader::SanitizeEntryName(safe, again) != safe) __builtin_trap();
    if (again) __builtin_trap();

    GMAReader::IsScannableFile(safe);
    GMAReader::IsBinaryModuleName(safe);
    GMAReader::IsNativeBinaryName(safe);
    GMAReader::IsRuntimeDataPath(safe);
    GMAReader::IsArchiveFile(safe);

    if (!IsValidUtf8(sanitizeForReport(raw, 200))) __builtin_trap();

    return 0;
}
