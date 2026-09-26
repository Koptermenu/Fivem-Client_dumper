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

} // namespace fivem
