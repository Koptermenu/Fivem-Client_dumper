#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace fivem {

// Reports bytes as they arrive (cumulative per call, across retries).
using ByteProgress = std::function<void(size_t)>;

struct HttpResponse {
    int status = 0;
    std::vector<uint8_t> body;
    std::string error;  // non-empty when request failed

    bool ok() const { return error.empty() && status >= 200 && status < 300; }
};

// Minimal HTTP client using WinHTTP (supports http + https, self-signed certs).
class HttpClient {
public:
    HttpClient();
    ~HttpClient();

    // POST application/x-www-form-urlencoded
    HttpResponse postForm(const std::string& url, const std::string& formBody,
                          const std::map<std::string, std::string>& headers = {});

    // GET binary content; onProgress (optional) receives byte counts as they
    // arrive, so callers can show live speed on heavily throttled servers.
    HttpResponse get(const std::string& url,
                     const std::map<std::string, std::string>& headers = {},
                     const ByteProgress& onProgress = nullptr);

    // One-shot plain-HTTP GET over raw Winsock with hard connect/receive
    // deadlines (no WinHTTP connect-retry overshoot). For short anonymous
    // probes like /dynamic.json. Returns error for https urls.
    static HttpResponse plainGetRaw(const std::string& url,
                                    const std::map<std::string, std::string>& headers,
                                    int connectMs, int recvMs);

    void setHeader(const std::string& key, const std::string& value);

    // resolve, connect, send, receive timeouts in ms (default 15/30/30/30 s)
    void setTimeouts(int resolveMs, int connectMs, int sendMs, int recvMs) {
        timeouts_[0] = resolveMs; timeouts_[1] = connectMs;
        timeouts_[2] = sendMs; timeouts_[3] = recvMs;
    }

private:
    HttpResponse request(const std::string& method, const std::string& url,
                         const std::vector<uint8_t>* body,
                         const std::map<std::string, std::string>& headers,
                         const ByteProgress& onProgress);

    void* session_ = nullptr;  // HINTERNET
    std::map<std::string, std::string> defaultHeaders_;
    int timeouts_[4] = {15000, 30000, 30000, 30000};
};

} // namespace fivem
