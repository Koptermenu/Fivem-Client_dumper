#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace fivem {

// SHA-256 over bytes, returns 32 bytes
std::vector<uint8_t> sha256(const uint8_t* data, size_t len);
std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);

// Lowercase hex of SHA-256
std::string sha256Hex(const std::vector<uint8_t>& data);

// HMAC-SHA256, returns 32 bytes
std::vector<uint8_t> hmacSha256(const std::vector<uint8_t>& key, const std::string& msg);
std::vector<uint8_t> hmacSha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& msg);

// Streaming SHA-256, for files that must not be held in memory (the language model).
class Sha256Stream {
public:
    Sha256Stream();

    void update(const uint8_t* data, size_t len);
    // Finalises the digest; the object must not be updated afterwards.
    std::string finishHex();

private:
    uint32_t state_[8];
    uint64_t totalBits_;
    uint8_t block_[64];
    size_t blockLen_;
};

// Lowercase hex of a file's SHA-256, read in chunks. False when the file cannot be read.
bool sha256HexFile(const std::string& path, std::string& hexOut);

} // namespace fivem
