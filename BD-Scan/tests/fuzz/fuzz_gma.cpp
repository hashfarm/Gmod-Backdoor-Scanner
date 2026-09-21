#include "GMAReader.h"
#include "MemoryStream.h"

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>

static constexpr int64_t kExtractCap = 1024 * 1024;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string input(reinterpret_cast<const char*>(data), size);
    MemoryStream stream(input);
    std::istringstream reference(input);

    const GMAInfo info = GMAReader::ReadGMAInfo(stream, static_cast<int64_t>(size));
    const GMAInfo expected = GMAReader::ReadGMAInfo(reference, static_cast<int64_t>(size));
    if (info.valid != expected.valid || info.error != expected.error || info.files.size() != expected.files.size()) __builtin_trap();
    if (!info.valid) return 0;

    if (info.contentOffset < 0 || info.contentOffset > static_cast<int64_t>(size)) __builtin_trap();
    if (info.files.size() > GMAReader::kMaxFileEntries) __builtin_trap();

    int64_t total = 0;
    for (const GMAFileEntry& entry : info.files) {
        if (entry.size < 0) __builtin_trap();
        if (entry.offset != total) __builtin_trap();
        total += entry.size;
        if (info.contentOffset + total > static_cast<int64_t>(size)) __builtin_trap();

        const std::string content = GMAReader::ExtractFileContent(stream, entry, info.contentOffset, kExtractCap);
        if (content != GMAReader::ExtractFileContent(reference, entry, info.contentOffset, kExtractCap)) __builtin_trap();
        if (static_cast<int64_t>(content.size()) > kExtractCap) __builtin_trap();
        if (!content.empty() && static_cast<int64_t>(content.size()) != entry.size) __builtin_trap();

        GMAReader::IsScannableFile(entry.filename);
        GMAReader::GetExtension(entry.filename);
    }
    return 0;
}
