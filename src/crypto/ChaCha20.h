#pragma once

#include <cstdint>
#include <vector>

namespace fivem {

// ChaCha20 (20 rounds) stream XOR, matching PyCryptodome behavior. The nonce
// length selects one of two distinct, non-interchangeable state layouts:
// 12 bytes -> RFC 8439 IETF (32-bit counter at word 12, 96-bit nonce at words
// 13-15); 8 bytes -> original DJB/PyCryptodome (64-bit counter at words 12-13,
// 64-bit nonce at words 14-15). All counters start at 0.
std::vector<uint8_t> chacha20Xor(const std::vector<uint8_t>& key,
                                 const std::vector<uint8_t>& nonce,
                                 const std::vector<uint8_t>& data);

} // namespace fivem
