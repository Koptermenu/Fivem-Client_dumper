#pragma once

#include <cstdint>
#include <vector>

namespace fivem {

// AES-256-CBC decrypt with PKCS#7 unpad. Returns false only on bad key size,
// bad input length or BCrypt failure; invalid padding is tolerated and the
// unstripped plaintext is returned.
bool aesCbc256DecryptPkcs7(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv,
                           const std::vector<uint8_t>& data, std::vector<uint8_t>& out);

// AES-256-CBC decrypt raw (no padding removal); empty iv = zero IV
bool aesCbc256DecryptRaw(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv,
                         const std::vector<uint8_t>& data, std::vector<uint8_t>& out);

} // namespace fivem
