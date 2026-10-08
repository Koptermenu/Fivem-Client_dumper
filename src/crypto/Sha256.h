#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
namespace fivem {
std::vector<uint8_t> sha256(const uint8_t* data, size_t len);
std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
std::string sha256Hex(const std::vector<uint8_t>& data);
std::vector<uint8_t> hmacSha256(const std::vector<uint8_t>& key, const std::string& msg);
std::vector<uint8_t> hmacSha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& msg);
}
