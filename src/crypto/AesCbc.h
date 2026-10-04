#pragma once
#include <cstdint>
#include <vector>
namespace fivem {
bool aesCbc256DecryptPkcs7(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv,
                           const std::vector<uint8_t>& data, std::vector<uint8_t>& out);
bool aesCbc256DecryptRaw(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv,
                         const std::vector<uint8_t>& data, std::vector<uint8_t>& out);
}
