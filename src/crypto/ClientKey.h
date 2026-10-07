#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace fivem {
std::vector<uint8_t> deriveClientKey(uint32_t resourceId, const std::vector<uint8_t>& grantsClk,
                                     std::string& errOut);

// False once the derive endpoint has failed at the transport level, or has been switched
// off with CK_CLIENT_KEY_API_URL=off. The decryptor checks this so it reports the cause
// once instead of repeating the same per-resource warning for every resource.
bool deriveClientKeyEndpointAvailable();
const char* deriveClientKeyEndpoint();
} 