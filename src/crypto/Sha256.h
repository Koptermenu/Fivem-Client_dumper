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
class Sha256Stream {
public:
    Sha256Stream();
    void update(const uint8_t* data, size_t len);
    std::string finishHex();
private:
    uint32_t state_[8];
    uint64_t totalBits_;
    uint8_t block_[64];
    size_t blockLen_;
};
bool sha256HexFile(const std::string& path, std::string& hexOut);
}
