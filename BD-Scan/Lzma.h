#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

namespace lzma {

struct Header {
    uint32_t dictionarySize = 0;
    uint64_t uncompressedSize = 0;
    unsigned literalContextBits = 0;
    unsigned literalPositionBits = 0;
    unsigned positionBits = 0;
    bool sizeKnown = false;
};

static constexpr size_t kHeaderSize = 13;
static constexpr uint64_t kUnknownSize = 0xFFFFFFFFFFFFFFFFull;

inline bool ParseHeader(const std::string& input, Header& header) {
    if (input.size() < kHeaderSize) return false;

    unsigned properties = static_cast<unsigned char>(input[0]);
    if (properties >= 9 * 5 * 5) return false;

    header.literalContextBits = properties % 9;
    properties /= 9;
    header.literalPositionBits = properties % 5;
    header.positionBits = properties / 5;

    header.dictionarySize = 0;
    for (int i = 0; i < 4; ++i) {
        header.dictionarySize |= static_cast<uint32_t>(static_cast<unsigned char>(input[1 + i])) << (8 * i);
    }
    if (header.dictionarySize < (1u << 12)) header.dictionarySize = 1u << 12;

    header.uncompressedSize = 0;
    for (int i = 0; i < 8; ++i) {
        header.uncompressedSize |= static_cast<uint64_t>(static_cast<unsigned char>(input[5 + i])) << (8 * i);
    }
    header.sizeKnown = (header.uncompressedSize != kUnknownSize);
    return true;
}

class RangeDecoder {
public:
    RangeDecoder(const uint8_t* data, size_t size) : m_data(data), m_size(size) {}

    bool Init() {
        if (m_size < 5) return false;
        if (m_data[0] != 0) return false;
        m_code = 0;
        m_range = 0xFFFFFFFFu;
        m_position = 1;
        for (int i = 0; i < 4; ++i) m_code = (m_code << 8) | NextByte();
        return true;
    }

    bool Overrun() const { return m_overrun; }

    unsigned DecodeBit(uint16_t& probability) {
        Normalize();
        const uint32_t bound = (m_range >> 11) * probability;
        unsigned symbol;
        if (m_code < bound) {
            m_range = bound;
            probability = static_cast<uint16_t>(probability + ((2048 - probability) >> 5));
            symbol = 0;
        }
        else {
            m_range -= bound;
            m_code -= bound;
            probability = static_cast<uint16_t>(probability - (probability >> 5));
            symbol = 1;
        }
        return symbol;
    }

    unsigned DecodeDirectBits(unsigned count) {
        uint32_t result = 0;
        while (count-- > 0) {
            Normalize();
            m_range >>= 1;
            m_code -= m_range;
            const uint32_t mask = 0u - (m_code >> 31);
            m_code += m_range & mask;
            result = (result << 1) + (mask + 1);
        }
        return result;
    }

    unsigned DecodeBitTree(uint16_t* probabilities, unsigned bits) {
        unsigned index = 1;
        for (unsigned i = 0; i < bits; ++i) index = (index << 1) + DecodeBit(probabilities[index]);
        return index - (1u << bits);
    }

    unsigned DecodeBitTreeReverse(uint16_t* probabilities, unsigned bits) {
        unsigned index = 1;
        unsigned result = 0;
        for (unsigned i = 0; i < bits; ++i) {
            const unsigned bit = DecodeBit(probabilities[index]);
            index = (index << 1) + bit;
            result |= bit << i;
        }
        return result;
    }

private:
    void Normalize() {
        if (m_range < (1u << 24)) {
            m_range <<= 8;
            m_code = (m_code << 8) | NextByte();
        }
    }

    uint8_t NextByte() {
        if (m_position >= m_size) {
            m_overrun = true;
            return 0;
        }
        return m_data[m_position++];
    }

    const uint8_t* m_data;
    size_t m_size;
    size_t m_position = 0;
    uint32_t m_range = 0;
    uint32_t m_code = 0;
    bool m_overrun = false;
};

enum class Status {
    Ok,
    BadHeader,
    Truncated,
    Corrupt,
    LimitReached
};

inline const char* StatusText(Status status) {
    switch (status) {
        case Status::Ok:           return "ok";
        case Status::BadHeader:    return "bad LZMA header";
        case Status::Truncated:    return "truncated LZMA stream";
        case Status::Corrupt:      return "corrupt LZMA stream";
        case Status::LimitReached: return "LZMA output exceeds the size limit";
        default:                   return "unknown";
    }
}

class Decoder {
public:
    static constexpr unsigned kNumStates = 12;
    static constexpr unsigned kNumPosBitsMax = 4;

    Status Decode(const std::string& input, uint64_t maxOutput, std::string& output) {
        Header header;
        if (!ParseHeader(input, header)) return Status::BadHeader;
        if (header.literalContextBits + header.literalPositionBits > 8) return Status::BadHeader;
        if (header.positionBits > kNumPosBitsMax) return Status::BadHeader;

        uint64_t limit = maxOutput;
        if (header.sizeKnown) {
            if (header.uncompressedSize > maxOutput) return Status::LimitReached;
            limit = header.uncompressedSize;
        }

        const uint8_t* stream = reinterpret_cast<const uint8_t*>(input.data()) + kHeaderSize;
        const size_t streamSize = input.size() - kHeaderSize;

        RangeDecoder range(stream, streamSize);
        if (!range.Init()) return Status::Truncated;

        Reset(header);
        output.clear();
        output.reserve(static_cast<size_t>(std::min<uint64_t>(limit, 1u << 20)));

        const unsigned positionMask = (1u << header.positionBits) - 1;
        unsigned state = 0;
        uint32_t rep0 = 0, rep1 = 0, rep2 = 0, rep3 = 0;
        bool sawEndMarker = false;
        bool ranOut = false;

        while (true) {
            if (range.Overrun()) {
                ranOut = true;
                break;
            }
            if (output.size() >= limit) {
                if (!header.sizeKnown) return Status::LimitReached;
                break;
            }

            const unsigned position = static_cast<unsigned>(output.size()) & positionMask;

            if (range.DecodeBit(m_isMatch[(state << kNumPosBitsMax) + position]) == 0) {
                const unsigned previous = output.empty() ? 0u
                    : static_cast<unsigned char>(output[output.size() - 1]);
                uint16_t* probabilities = LiteralProbabilities(header, output.size(), previous);

                unsigned symbol = 1;
                if (state >= 7) {
                    if (rep0 > output.size()) return Status::Corrupt;
                    unsigned matchByte = static_cast<unsigned char>(output[output.size() - rep0 - 1]);
                    do {
                        const unsigned matchBit = (matchByte >> 7) & 1;
                        matchByte <<= 1;
                        const unsigned bit = range.DecodeBit(probabilities[((1 + matchBit) << 8) + symbol]);
                        symbol = (symbol << 1) | bit;
                        if (matchBit != bit) break;
                    } while (symbol < 0x100);
                }
                while (symbol < 0x100) symbol = (symbol << 1) | range.DecodeBit(probabilities[symbol]);

                output += static_cast<char>(symbol & 0xFF);
                state = state < 4 ? 0 : (state < 10 ? state - 3 : state - 6);
                continue;
            }

            uint32_t length = 0;
            if (range.DecodeBit(m_isRep[state]) != 0) {
                if (output.empty()) return Status::Corrupt;

                if (range.DecodeBit(m_isRepG0[state]) == 0) {
                    if (range.DecodeBit(m_isRep0Long[(state << kNumPosBitsMax) + position]) == 0) {
                        state = state < 7 ? 9 : 11;
                        if (rep0 > output.size() - 1) return Status::Corrupt;
                        output += output[output.size() - rep0 - 1];
                        continue;
                    }
                }
                else {
                    uint32_t distance;
                    if (range.DecodeBit(m_isRepG1[state]) == 0) {
                        distance = rep1;
                    }
                    else {
                        if (range.DecodeBit(m_isRepG2[state]) == 0) {
                            distance = rep2;
                        }
                        else {
                            distance = rep3;
                            rep3 = rep2;
                        }
                        rep2 = rep1;
                    }
                    rep1 = rep0;
                    rep0 = distance;
                }
                length = DecodeLength(range, m_repLength, position);
                state = state < 7 ? 8 : 11;
            }
            else {
                rep3 = rep2;
                rep2 = rep1;
                rep1 = rep0;
                length = DecodeLength(range, m_length, position);
                state = state < 7 ? 7 : 10;

                const unsigned lengthSlot = std::min<unsigned>(length, 3);
                const unsigned slot = range.DecodeBitTree(m_posSlot[lengthSlot], 6);
                if (slot < 4) {
                    rep0 = slot;
                }
                else {
                    const unsigned directBits = (slot >> 1) - 1;
                    rep0 = (2 | (slot & 1)) << directBits;
                    if (slot < 14) {
                        rep0 += DecodeBitTreeReverseAt(range, m_specPos + rep0 - slot - 1, directBits);
                    }
                    else {
                        rep0 += range.DecodeDirectBits(directBits - 4) << 4;
                        rep0 += range.DecodeBitTreeReverse(m_align, 4);
                    }
                }

                if (rep0 == 0xFFFFFFFFu) {
                    sawEndMarker = true;
                    break;
                }
                if (rep0 >= header.dictionarySize && rep0 >= output.size()) return Status::Corrupt;
            }

            const uint64_t matchLength = static_cast<uint64_t>(length) + 2;
            if (rep0 >= output.size()) return Status::Corrupt;
            if (output.size() + matchLength > limit) {
                return header.sizeKnown ? Status::Corrupt : Status::LimitReached;
            }

            const size_t start = output.size() - rep0 - 1;
            for (uint64_t i = 0; i < matchLength; ++i) {
                output += output[start + static_cast<size_t>(i)];
            }
        }

        if (ranOut && !sawEndMarker) return Status::Truncated;
        if (header.sizeKnown && output.size() != header.uncompressedSize) return Status::Truncated;
        return Status::Ok;
    }

private:
    uint16_t* LiteralProbabilities(const Header& header, size_t produced, unsigned previous) {
        const unsigned positionPart = static_cast<unsigned>(produced) & ((1u << header.literalPositionBits) - 1);
        const unsigned contextPart = previous >> (8 - header.literalContextBits);
        const size_t index = ((positionPart << header.literalContextBits) + contextPart) * 0x300;
        return m_literal.data() + index;
    }

    static unsigned DecodeBitTreeReverseAt(RangeDecoder& range, uint16_t* probabilities, unsigned bits) {
        return range.DecodeBitTreeReverse(probabilities, bits);
    }

    struct LengthCoder {
        uint16_t choice = 1024;
        uint16_t choice2 = 1024;
        uint16_t low[1u << kNumPosBitsMax][8];
        uint16_t mid[1u << kNumPosBitsMax][8];
        uint16_t high[256];

        void Reset() {
            choice = 1024;
            choice2 = 1024;
            for (auto& row : low) for (uint16_t& p : row) p = 1024;
            for (auto& row : mid) for (uint16_t& p : row) p = 1024;
            for (uint16_t& p : high) p = 1024;
        }
    };

    static uint32_t DecodeLength(RangeDecoder& range, LengthCoder& coder, unsigned position) {
        if (range.DecodeBit(coder.choice) == 0) {
            return range.DecodeBitTree(coder.low[position], 3);
        }
        if (range.DecodeBit(coder.choice2) == 0) {
            return 8 + range.DecodeBitTree(coder.mid[position], 3);
        }
        return 16 + range.DecodeBitTree(coder.high, 8);
    }

    void Reset(const Header& header) {
        const size_t literalStates = static_cast<size_t>(1)
            << (header.literalContextBits + header.literalPositionBits);
        m_literal.assign(literalStates * 0x300, 1024);

        for (uint16_t& p : m_isMatch) p = 1024;
        for (uint16_t& p : m_isRep) p = 1024;
        for (uint16_t& p : m_isRepG0) p = 1024;
        for (uint16_t& p : m_isRepG1) p = 1024;
        for (uint16_t& p : m_isRepG2) p = 1024;
        for (uint16_t& p : m_isRep0Long) p = 1024;
        for (auto& row : m_posSlot) for (uint16_t& p : row) p = 1024;
        for (uint16_t& p : m_specPos) p = 1024;
        for (uint16_t& p : m_align) p = 1024;
        m_length.Reset();
        m_repLength.Reset();
    }

    std::vector<uint16_t> m_literal;
    uint16_t m_isMatch[kNumStates << kNumPosBitsMax];
    uint16_t m_isRep[kNumStates];
    uint16_t m_isRepG0[kNumStates];
    uint16_t m_isRepG1[kNumStates];
    uint16_t m_isRepG2[kNumStates];
    uint16_t m_isRep0Long[kNumStates << kNumPosBitsMax];
    uint16_t m_posSlot[4][64];
    uint16_t m_specPos[115];
    uint16_t m_align[16];
    LengthCoder m_length;
    LengthCoder m_repLength;
};

inline Status Decompress(const std::string& input, uint64_t maxOutput, std::string& output) {
    Decoder decoder;
    return decoder.Decode(input, maxOutput, output);
}

}
