#pragma once

#include <cstdint>
#include <vector>

namespace fivem {

// ChaCha20 (20 rounds) stream XOR, matching PyCryptodome behavior:
// nonce must be 8 or 12 bytes. Counter (4 bytes, LE, starting at 0) is placed
// before the nonce field; an 8-byte nonce is zero-padded to 12 bytes.
std::vector<uint8_t> chacha20Xor(const std::vector<uint8_t>& key,
                                 const std::vector<uint8_t>& nonce,
                                 const std::vector<uint8_t>& data);

inline std::vector<uint8_t> chacha20Decrypt(const std::vector<uint8_t>& key,
                                            const std::vector<uint8_t>& nonce,
                                            const std::vector<uint8_t>& data) {
    return chacha20Xor(key, nonce, data);
}

} // namespace fivem
