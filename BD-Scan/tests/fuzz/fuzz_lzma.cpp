#include "Lzma.h"

#include <cstddef>
#include <cstdint>
#include <string>

static constexpr uint64_t kOutputCap = 4ull * 1024 * 1024;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string input(reinterpret_cast<const char*>(data), size);
    std::string output;
    const lzma::Status status = lzma::Decompress(input, kOutputCap, output);

    if (status == lzma::Status::Ok && output.size() > kOutputCap) __builtin_trap();
    if (status == lzma::Status::LimitReached && output.size() > kOutputCap) __builtin_trap();

    lzma::Header header;
    if (lzma::ParseHeader(input, header)) {
        if (header.literalContextBits > 8 || header.literalPositionBits > 4 || header.positionBits > 4) {
            __builtin_trap();
        }
    }
    return 0;
}
