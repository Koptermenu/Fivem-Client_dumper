#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace fivem {
std::vector<uint8_t> deriveClientKey(uint32_t resourceId, const std::vector<uint8_t>& grantsClk,
                                     std::string& errOut);




bool deriveClientKeyEndpointAvailable();
const char* deriveClientKeyEndpoint();
}