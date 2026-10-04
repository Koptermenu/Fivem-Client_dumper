#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace fivem {

// Derives the 32-byte client key of a resource from its 48-byte grants_clk.
//
// The derivation itself is not a local formula: the escrow client keys are produced
// by the key-derivation service, which is queried with the resource ID and the
// grants_clk shipped in the grants token. Deriving them locally with a hardcoded
// AES key yields unrelated bytes, so client-side Lua cannot be recovered without
// this call.
//
// Base URL: CK_CLIENT_KEY_API_URL, else CK_GRANTS_CLK_API_URL, else the built-in
// endpoint. Returns an empty vector on failure and fills errOut with the reason.
std::vector<uint8_t> deriveClientKey(uint32_t resourceId, const std::vector<uint8_t>& grantsClk,
                                     std::string& errOut);

} // namespace fivem