#include "ClientKey.h"
#include "../core/HttpClient.h"
#include "../utils/Str.h"
#include "../utils/Json.h"
#include <cstdlib>
namespace fivem {
static const char* kDefaultDeriveApi = "https://grantsclk.ckcloud.de5.net";
std::vector<uint8_t> deriveClientKey(uint32_t resourceId, const std::vector<uint8_t>& grantsClk,
                                     std::string& errOut) {
    errOut.clear();
    if (grantsClk.size() != 48) {
        errOut = "a grants_clk kanonikus alakja 48 bajtos, a tokenban " +
                 std::to_string(grantsClk.size()) + " bajtos van";
        return {};
    }
    std::string root;
    if (const char* env = getenv("CK_CLIENT_KEY_API_URL")) root = env;
    else if (const char* env = getenv("CK_GRANTS_CLK_API_URL")) root = env;
    while (!root.empty() && root.back() == '/') root.pop_back();
    if (root.empty()) root = kDefaultDeriveApi;
    const std::string idStr = std::to_string(resourceId);
    const std::string body = "{\"resourceId\":\"" + idStr + "\",\"grants_clk\":\"" +
                             hexEncode(grantsClk) + "\"}";
    HttpClient http;
    HttpResponse resp = http.postJson(root + "/v1/derive", body);
    if (!resp.ok()) {
        errOut = "derive service returned HTTP " + std::to_string(resp.status) +
                 (resp.error.empty() ? "" : (" (" + resp.error + ")"));
        return {};
    }
    Json js;
    try {
        js = Json::parse(std::string(resp.body.begin(), resp.body.end()));
    } catch (const std::exception& e) {
        errOut = std::string("derive service returned invalid JSON: ") + e.what();
        return {};
    }
    const Json& returnedId = js.at("resourceId");
    std::string gotId;
    if (returnedId.isString()) gotId = returnedId.asString();
    else if (returnedId.isNumber())
        gotId = std::to_string(static_cast<uint64_t>(returnedId.asNumber()));
    if (gotId != idStr) {
        errOut = "derive service returned a mismatched resourceId (got '" + gotId +
                 "', expected '" + idStr + "')";
        return {};
    }
    std::string keyHex = toLower(js.strAt("key", ""));
    if (keyHex.size() != 64 ||
        keyHex.find_first_not_of("0123456789abcdef") != std::string::npos) {
        errOut = "derive service returned an invalid key";
        return {};
    }
    return hexDecode(keyHex);
}
} 