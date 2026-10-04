#include "Sha256.h"

#include <cstring>
#include <fstream>
#include <vector>

namespace fivem {

namespace {

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

constexpr char kDigits[] = "0123456789abcdef";

inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

void transform(uint32_t h[8], const uint8_t chunk[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (uint32_t(chunk[i * 4]) << 24) | (uint32_t(chunk[i * 4 + 1]) << 16) |
               (uint32_t(chunk[i * 4 + 2]) << 8) | uint32_t(chunk[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

std::vector<uint8_t> sha256Impl(const uint8_t* msg, size_t len) {
    uint32_t h[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                     0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    std::vector<uint8_t> data(msg, msg + len);
    uint64_t bitLen = uint64_t(len) * 8;
    data.push_back(0x80);
    while (data.size() % 64 != 56) data.push_back(0);
    for (int i = 7; i >= 0; --i) data.push_back(uint8_t((bitLen >> (i * 8)) & 0xFF));
    for (size_t off = 0; off < data.size(); off += 64) transform(h, data.data() + off);

    std::vector<uint8_t> out(32);
    for (int i = 0; i < 8; ++i) {
        out[i*4]   = uint8_t(h[i] >> 24);
        out[i*4+1] = uint8_t(h[i] >> 16);
        out[i*4+2] = uint8_t(h[i] >> 8);
        out[i*4+3] = uint8_t(h[i]);
    }
    return out;
}

} // namespace

std::vector<uint8_t> sha256(const uint8_t* data, size_t len) { return sha256Impl(data, len); }
std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) { return sha256Impl(data.data(), data.size()); }

std::string sha256Hex(const std::vector<uint8_t>& data) {
    auto h = sha256(data);
    std::string out;
    out.reserve(64);
    for (uint8_t b : h) { out += kDigits[b >> 4]; out += kDigits[b & 0xF]; }
    return out;
}

std::vector<uint8_t> hmacSha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& msg) {
    const size_t B = 64;
    std::vector<uint8_t> k = key;
    if (k.size() > B) k = sha256Impl(k.data(), k.size());
    k.resize(B, 0);
    std::vector<uint8_t> ipad(B + msg.size()), opad(B + 32);
    for (size_t i = 0; i < B; ++i) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    std::memcpy(ipad.data() + B, msg.data(), msg.size());
    auto inner = sha256Impl(ipad.data(), ipad.size());
    std::memcpy(opad.data() + B, inner.data(), 32);
    return sha256Impl(opad.data(), opad.size());
}

std::vector<uint8_t> hmacSha256(const std::vector<uint8_t>& key, const std::string& msg) {
    return hmacSha256(key, std::vector<uint8_t>(msg.begin(), msg.end()));
}

Sha256Stream::Sha256Stream() : totalBits_(0), blockLen_(0) {
    state_[0] = 0x6a09e667u; state_[1] = 0xbb67ae85u; state_[2] = 0x3c6ef372u;
    state_[3] = 0xa54ff53au; state_[4] = 0x510e527fu; state_[5] = 0x9b05688cu;
    state_[6] = 0x1f83d9abu; state_[7] = 0x5be0cd19u;
    std::memset(block_, 0, sizeof(block_));
}

void Sha256Stream::update(const uint8_t* data, size_t len) {
    totalBits_ += static_cast<uint64_t>(len) * 8;
    while (len > 0) {
        const size_t room = 64 - blockLen_;
        const size_t take = (len < room) ? len : room;
        std::memcpy(block_ + blockLen_, data, take);
        blockLen_ += take;
        data += take;
        len -= take;
        if (blockLen_ == 64) {
            transform(state_, block_);
            blockLen_ = 0;
        }
    }
}

std::string Sha256Stream::finishHex() {
    const uint64_t bits = totalBits_;

    // Pad directly into the block buffer: routing the padding through update() would
    // keep extending totalBits_, and the length has to stay the original one.
    block_[blockLen_++] = 0x80;
    if (blockLen_ > 56) {
        while (blockLen_ < 64) block_[blockLen_++] = 0;
        transform(state_, block_);
        blockLen_ = 0;
    }
    while (blockLen_ < 56) block_[blockLen_++] = 0;
    for (int i = 0; i < 8; ++i)
        block_[56 + i] = static_cast<uint8_t>((bits >> (56 - i * 8)) & 0xFF);
    transform(state_, block_);
    blockLen_ = 0;

    std::string out;
    out.reserve(64);
    for (int i = 0; i < 8; ++i) {
        for (int b = 3; b >= 0; --b) {
            const uint8_t byte = static_cast<uint8_t>((state_[i] >> (b * 8)) & 0xFF);
            out += kDigits[byte >> 4];
            out += kDigits[byte & 0x0F];
        }
    }
    return out;
}

bool sha256HexFile(const std::string& path, std::string& hexOut) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return false;
    Sha256Stream sha;
    std::vector<char> buf(1 << 20);
    for (;;) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize got = in.gcount();
        if (got <= 0) break;
        sha.update(reinterpret_cast<const uint8_t*>(buf.data()), static_cast<size_t>(got));
    }
    hexOut = sha.finishHex();
    return true;
}

} // namespace fivem
