#pragma once
#include <cstdint>
#include <vector>
namespace fivem {
std::vector<uint8_t> chacha20Xor(const std::vector<uint8_t>& key,
                                 const std::vector<uint8_t>& nonce,
                                 const std::vector<uint8_t>& data);
}
