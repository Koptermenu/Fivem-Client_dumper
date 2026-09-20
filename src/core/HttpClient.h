#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace fivem {

using ByteProgress = std::function<void(size_t)>;
using SizeCallback = std::function<void(size_t)>;

struct HttpResponse {
    int status = 0;
    size_t contentLength = 0;
    std::vector<uint8_t> body;
    std::string error;

    bool ok() const { return error.empty() && status >= 200 && status < 300; }
};

class HttpClient {
public:
    HttpClient();
    ~HttpClient();

    HttpResponse postForm(const std::string& url, const std::string& formBody,
                          const std::map<std::string, std::string>& headers = {});

    HttpResponse get(const std::string& url,
                     const std::map<std::string, std::string>& headers = {},
                     const ByteProgress& onProgress = nullptr,
                     const SizeCallback& onStart = nullptr);

    static HttpResponse plainGetRaw(const std::string& url,
                                    const std::map<std::string, std::string>& headers,
                                    int connectMs, int recvMs);

    void setHeader(const std::string& key, const std::string& value);

    void setTimeouts(int resolveMs, int connectMs, int sendMs, int recvMs) {
        timeouts_[0] = resolveMs; timeouts_[1] = connectMs;
        timeouts_[2] = sendMs; timeouts_[3] = recvMs;
    }

private:
    HttpResponse request(const std::string& method, const std::string& url,
                         const std::vector<uint8_t>* body,
                         const std::map<std::string, std::string>& headers,
                         const ByteProgress& onProgress,
                         const SizeCallback& onStart);

    void* session_ = nullptr;
    std::map<std::string, std::string> defaultHeaders_;
    int timeouts_[4] = {15000, 30000, 30000, 30000};
};

} // namespace fivem