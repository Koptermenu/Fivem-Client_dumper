#include "ChaCha20.h"
#include "../utils/Str.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>
namespace fivem {
namespace {
inline uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
#define QR(a, b, c, d)                  \
    do {                                \
        a += b; d ^= a; d = rotl(d, 16);\
        c += d; b ^= c; b = rotl(b, 12);\
        a += b; d ^= a; d = rotl(d, 8); \
        c += d; b ^= c; b = rotl(b, 7); \
    } while (0)
void blockKeystream(const uint32_t state[16], uint8_t out[64]) {
    uint32_t x[16];
    std::memcpy(x, state, 64);
    for (int i = 0; i < 10; ++i) {
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; ++i) {
        uint32_t v = x[i] + state[i];
        out[i * 4] = static_cast<uint8_t>(v);
        out[i * 4 + 1] = static_cast<uint8_t>(v >> 8);
        out[i * 4 + 2] = static_cast<uint8_t>(v >> 16);
        out[i * 4 + 3] = static_cast<uint8_t>(v >> 24);
    }
}
}
std::vector<uint8_t> chacha20Xor(const std::vector<uint8_t>& key,
                                 const std::vector<uint8_t>& nonce,
                                 const std::vector<uint8_t>& data) {
    if (key.size() != 32) {
        throw std::runtime_error("chacha20: key must be 32 bytes");
    }
    if (nonce.size() != 8 && nonce.size() != 12) {
        throw std::runtime_error("chacha20: nonce must be 8 or 12 bytes");
    }
    uint32_t state[16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for (int i = 0; i < 8; ++i) state[4 + i] = le32(key.data() + i * 4);
    bool rfcMode = (nonce.size() == 12);
    if (rfcMode) {
        state[12] = 0;
        state[13] = le32(nonce.data() + 0);
        state[14] = le32(nonce.data() + 4);
        state[15] = le32(nonce.data() + 8);
    } else {
        state[12] = 0;
        state[13] = 0;
        state[14] = le32(nonce.data() + 0);
        state[15] = le32(nonce.data() + 4);
    }
    std::vector<uint8_t> out(data.size());
    uint8_t ks[64];
    for (size_t off = 0; off < data.size(); off += 64) {
        blockKeystream(state, ks);
        size_t n = std::min<size_t>(64, data.size() - off);
        for (size_t i = 0; i < n; ++i) out[off + i] = data[off + i] ^ ks[i];
        if (++state[12] == 0 && !rfcMode) ++state[13];
    }
    return out;
}
}
