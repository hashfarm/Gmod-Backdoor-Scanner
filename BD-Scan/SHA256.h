#pragma once
#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>

class SHA256 {
public:
    SHA256() { Reset(); }

    void Reset() {
        m_dataLen = 0;
        m_bitLen = 0;
        m_state[0] = 0x6a09e667;
        m_state[1] = 0xbb67ae85;
        m_state[2] = 0x3c6ef372;
        m_state[3] = 0xa54ff53a;
        m_state[4] = 0x510e527f;
        m_state[5] = 0x9b05688c;
        m_state[6] = 0x1f83d9ab;
        m_state[7] = 0x5be0cd19;
        for (int i = 0; i < 64; i++) m_data[i] = 0;
    }

    void Update(const uint8_t* data, size_t length) {
        for (size_t i = 0; i < length; i++) {
            m_data[m_dataLen++] = data[i];
            if (m_dataLen == 64) {
                Transform();
                m_bitLen += 512;
                m_dataLen = 0;
            }
        }
    }

    void Update(const std::string& data) {
        Update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }

    std::string Finalize() {
        uint32_t i = m_dataLen;
        if (m_dataLen < 56) {
            m_data[i++] = 0x80;
            while (i < 56) m_data[i++] = 0x00;
        } else {
            m_data[i++] = 0x80;
            while (i < 64) m_data[i++] = 0x00;
            Transform();
            for (i = 0; i < 56; i++) m_data[i] = 0;
        }
        m_bitLen += static_cast<uint64_t>(m_dataLen) * 8;
        m_data[63] = static_cast<uint8_t>(m_bitLen);
        m_data[62] = static_cast<uint8_t>(m_bitLen >> 8);
        m_data[61] = static_cast<uint8_t>(m_bitLen >> 16);
        m_data[60] = static_cast<uint8_t>(m_bitLen >> 24);
        m_data[59] = static_cast<uint8_t>(m_bitLen >> 32);
        m_data[58] = static_cast<uint8_t>(m_bitLen >> 40);
        m_data[57] = static_cast<uint8_t>(m_bitLen >> 48);
        m_data[56] = static_cast<uint8_t>(m_bitLen >> 56);
        Transform();

        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (i = 0; i < 8; i++) {
            ss << std::setw(8) << m_state[i];
        }
        Reset();
        return ss.str();
    }

    static std::string Hash(const std::string& data) {
        SHA256 ctx;
        ctx.Update(data);
        return ctx.Finalize();
    }

private:
    uint8_t  m_data[64];
    uint32_t m_dataLen;
    uint64_t m_bitLen;
    uint32_t m_state[8];

    static uint32_t Rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t Choice(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    static uint32_t Majority(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint32_t BigSigma0(uint32_t x) { return Rotr(x, 2) ^ Rotr(x, 13) ^ Rotr(x, 22); }
    static uint32_t BigSigma1(uint32_t x) { return Rotr(x, 6) ^ Rotr(x, 11) ^ Rotr(x, 25); }
    static uint32_t SmallSigma0(uint32_t x) { return Rotr(x, 7) ^ Rotr(x, 18) ^ (x >> 3); }
    static uint32_t SmallSigma1(uint32_t x) { return Rotr(x, 17) ^ Rotr(x, 19) ^ (x >> 10); }

    static const uint32_t K[64];

    void Transform() {
        uint32_t m[64];
        for (int i = 0, j = 0; i < 16; i++, j += 4) {
            m[i] = (static_cast<uint32_t>(m_data[j]) << 24) |
                   (static_cast<uint32_t>(m_data[j + 1]) << 16) |
                   (static_cast<uint32_t>(m_data[j + 2]) << 8) |
                   (static_cast<uint32_t>(m_data[j + 3]));
        }
        for (int i = 16; i < 64; i++) {
            m[i] = SmallSigma1(m[i - 2]) + m[i - 7] + SmallSigma0(m[i - 15]) + m[i - 16];
        }

        uint32_t a = m_state[0], b = m_state[1], c = m_state[2], d = m_state[3];
        uint32_t e = m_state[4], f = m_state[5], g = m_state[6], h = m_state[7];

        for (int i = 0; i < 64; i++) {
            uint32_t t1 = h + BigSigma1(e) + Choice(e, f, g) + K[i] + m[i];
            uint32_t t2 = BigSigma0(a) + Majority(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        m_state[0] += a; m_state[1] += b; m_state[2] += c; m_state[3] += d;
        m_state[4] += e; m_state[5] += f; m_state[6] += g; m_state[7] += h;
    }
};

inline const uint32_t SHA256::K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
