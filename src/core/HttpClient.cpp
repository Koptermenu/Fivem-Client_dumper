#include "HttpClient.h"

#include <windows.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

namespace fivem {

namespace {

void ensureWinsock() {
    static std::once_flag once;
    std::call_once(once, [] {
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
    });
}

struct UrlParts {
    bool https = false;
    std::wstring host;
    INTERNET_PORT port = 0;
    std::wstring path;
};

constexpr size_t kMaxChunkedResponseBytes = 512u * 1024u * 1024u;

bool startsWithNoCase(const std::string& s, const char* prefix) {
    size_t n = std::strlen(prefix);
    if (s.size() < n) return false;
    for (size_t i = 0; i < n; ++i) {
        if (std::tolower(static_cast<unsigned char>(s[i])) !=
            std::tolower(static_cast<unsigned char>(prefix[i]))) {
            return false;
        }
    }
    return true;
}

bool parseUrl(const std::string& url, UrlParts& parts) {
    std::string s = url;
    if (startsWithNoCase(s, "https://")) {
        parts.https = true;
        s = s.substr(8);
        parts.port = INTERNET_DEFAULT_HTTPS_PORT;
    } else if (startsWithNoCase(s, "http://")) {
        parts.https = false;
        s = s.substr(7);
        parts.port = INTERNET_DEFAULT_HTTP_PORT;
    } else {
        return false;
    }
    size_t slash = s.find('/');
    std::string hostport = (slash == std::string::npos) ? s : s.substr(0, slash);
    std::string rest = (slash == std::string::npos) ? "/" : s.substr(slash);
    size_t colon = hostport.find(':');
    std::string hostStr = hostport;
    if (colon != std::string::npos) {
        hostStr = hostport.substr(0, colon);
        std::string portStr = hostport.substr(colon + 1);
        if (portStr.empty() || portStr.size() > 5) return false;
        unsigned long port = 0;
        for (char c : portStr) {
            if (c < '0' || c > '9') return false;
            port = port * 10 + static_cast<unsigned long>(c - '0');
        }
        if (port == 0 || port > 65535) return false;
        parts.port = static_cast<INTERNET_PORT>(port);
    }
    if (hostStr.empty()) return false;
    parts.host.assign(hostStr.begin(), hostStr.end());
    parts.path.assign(rest.begin(), rest.end());
    return true;
}

std::wstring utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), w.data(), len);
    return w;
}

std::string wideToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                  nullptr, 0, nullptr, nullptr);
    std::string s(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                        s.data(), len, nullptr, nullptr);
    return s;
}

HttpResponse httpRawRequest(const std::string& method, const std::string& host, INTERNET_PORT port,
                            const std::string& path, const std::map<std::string, std::string>& headers,
                            const std::vector<uint8_t>* body, int connectMs, int recvMs,
                            const SizeCallback& onStart) {
    HttpResponse resp;
    ensureWinsock();
    auto started = std::chrono::steady_clock::now();

    std::string req = method + " " + path + " HTTP/1.1\r\nHost: " + host + ":" + std::to_string(port) + "\r\n";
    for (const auto& kv : headers) {
        std::string value;
        for (char c : kv.second) if (c != '\r' && c != '\n') value += c;
        req += kv.first + ": " + value + "\r\n";
    }
    if (body) {
        req += "Content-Length: " + std::to_string(body->size()) + "\r\n";
    }
    req += "Connection: close\r\n\r\n";
    if (body) req.append(reinterpret_cast<const char*>(body->data()), body->size());

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) {
        resp.error = "resolve failed: " + host;
        return resp;
    }

    SOCKET s = INVALID_SOCKET;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        long long connectRemain = static_cast<long long>(connectMs) -
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - started).count();
        if (connectRemain < 100) { connectRemain = 100; }
        s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        u_long nonblk = 1;
        ioctlsocket(s, FIONBIO, &nonblk);
        int rc = ::connect(s, ai->ai_addr, (int)ai->ai_addrlen);
        bool ready = (rc == 0);
        if (!ready && WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set wf;
            FD_ZERO(&wf);
            FD_SET(s, &wf);
            timeval tv{static_cast<long>(connectRemain / 1000),
                       static_cast<long>((connectRemain % 1000) * 1000)};
            if (select(0, nullptr, &wf, nullptr, &tv) == 1) {
                int err = 0;
                int len = sizeof(err);
                getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
                ready = (err == 0);
            }
        }
        if (!ready) {
            closesocket(s);
            s = INVALID_SOCKET;
            continue;
        }
        u_long blk = 0;
        ioctlsocket(s, FIONBIO, &blk);
        break;
    }
    freeaddrinfo(res);
    if (s == INVALID_SOCKET) {
        resp.error = "connect failed: " + host;
        return resp;
    }

    long long elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::steady_clock::now() - started).count();
    long long remain = static_cast<long long>(recvMs) - elapsedMs;
    if (remain < 100) {
        resp.error = "connect failed: " + host;
        closesocket(s);
        return resp;
    }
    DWORD tv = static_cast<DWORD>(remain);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));

    auto fail = [&](const std::string& msg) {
        resp.error = msg;
        closesocket(s);
        return resp;
    };

    size_t off = 0;
    while (off < req.size()) {
        int n = ::send(s, req.data() + off, static_cast<int>(req.size() - off), 0);
        if (n == SOCKET_ERROR) return fail("send failed (" + std::to_string(WSAGetLastError()) + ")");
        off += static_cast<size_t>(n);
    }

    auto pull = [&](std::string& buf) -> int {
        char tmp[8192];
        int n = ::recv(s, tmp, sizeof(tmp), 0);
        if (n > 0) buf.append(tmp, static_cast<size_t>(n));
        return n;
    };

    std::string buf;
    size_t hdrEnd = std::string::npos;
    while (hdrEnd == std::string::npos) {
        int n = pull(buf);
        if (n <= 0) return fail(n < 0 ? "receive failed (" + std::to_string(WSAGetLastError()) + ")"
                                      : "empty response from server");
        hdrEnd = buf.find("\r\n\r\n");
        if (hdrEnd == std::string::npos && buf.size() > (1u << 20)) return fail("response headers too large");
    }
    hdrEnd += 4;

    std::string head = buf.substr(0, hdrEnd);
    if (head.rfind("HTTP/", 0) != 0) return fail("malformed response");
    size_t sp1 = head.find(' ');
    if (sp1 != std::string::npos) resp.status = std::atoi(head.c_str() + sp1 + 1);

    std::string lower;
    for (char c : head) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    bool chunked = lower.find("transfer-encoding:") != std::string::npos &&
                   lower.find("chunked") != std::string::npos;
    bool haveLen = false;
    size_t contentLen = 0;
    if (auto p = lower.find("content-length:"); p != std::string::npos) {
        const size_t headSize = head.size();
        size_t q = p + 15;
        while (q < headSize && (head[q] == ' ' || head[q] == '\t')) ++q;
        const size_t digitsBegin = q;
        while (q < headSize && head[q] >= '0' && head[q] <= '9') ++q;
        if (q == digitsBegin) return fail("malformed content-length");
        size_t after = q;
        while (after < headSize && (head[after] == ' ' || head[after] == '\t')) ++after;
        if (after >= headSize || (head[after] != '\r' && head[after] != '\n')) {
            return fail("malformed content-length");
        }
        unsigned long long value = 0;
        for (size_t i = digitsBegin; i < q; ++i) {
            const unsigned digit = static_cast<unsigned>(head[i] - '0');
            if (value > (SIZE_MAX - digit) / 10) return fail("content-length too large");
            value = value * 10 + digit;
        }
        if (value == 0) return fail("malformed content-length: zero length");
        contentLen = static_cast<size_t>(value);
        haveLen = true;
        resp.contentLength = contentLen;
        if (onStart) onStart(contentLen);
    }

    std::string payload = buf.substr(hdrEnd);
    if (chunked) {
        std::string out;
        size_t pos = 0;
        for (;;) {
            size_t eol;
            while ((eol = payload.find("\r\n", pos)) == std::string::npos) {
                if (payload.size() - pos > (1u << 20)) return fail("chunked size line too large");
                if (pull(payload) <= 0) return fail("chunked stream truncated");
            }
            size_t tok = eol - pos;
            size_t semi = payload.find(';', pos);
            if (semi != std::string::npos && semi < eol) tok = semi - pos;
            if (tok == 0) return fail("malformed chunk size");
            const char* p = payload.c_str() + pos;
            char* end = nullptr;
            unsigned long long raw = std::strtoull(p, &end, 16);
            if (end != p + tok) return fail("malformed chunk size");
            if (raw > kMaxChunkedResponseBytes) return fail("chunked response too large");
            size_t csz = static_cast<size_t>(raw);
            pos = eol + 2;
            if (csz == 0) break;
            if (csz > kMaxChunkedResponseBytes - out.size()) return fail("chunked response too large");
            if (csz > SIZE_MAX - pos - 2) return fail("chunked response too large");
            while (payload.size() - pos < csz + 2)
                if (pull(payload) <= 0) return fail("chunked stream truncated");
            out.append(payload, pos, csz);
            pos += csz + 2;
        }
        payload = std::move(out);
    } else if (haveLen) {
        while (payload.size() < contentLen) {
            int n = pull(payload);
            if (n <= 0) {
                if (n < 0) return fail("receive failed (" + std::to_string(WSAGetLastError()) + ")");
                resp.error = "truncated response (" + std::to_string(payload.size()) + " of " +
                             std::to_string(contentLen) + " bytes)";
                break;
            }
        }
    } else {
        for (;;) {
            if (payload.size() > kMaxChunkedResponseBytes) return fail("response too large");
            if (pull(payload) <= 0) break;
        }
    }

    closesocket(s);
    resp.body.assign(payload.begin(), payload.end());
    return resp;
}

} // namespace

HttpClient::HttpClient() {
    session_ = WinHttpOpen(L"FiveMDumper/1.0",
                           WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
}

HttpClient::~HttpClient() {
    if (session_) WinHttpCloseHandle(static_cast<HINTERNET>(session_));
}

void HttpClient::setHeader(const std::string& key, const std::string& value) {
    defaultHeaders_[key] = value;
}

HttpResponse HttpClient::request(const std::string& method, const std::string& url,
                                 const std::vector<uint8_t>* body,
                                 const std::map<std::string, std::string>& headers,
                                 const ByteProgress& onProgress,
                                 const SizeCallback& onStart) {
    HttpResponse resp;
    UrlParts parts;
    if (!parseUrl(url, parts)) {
        resp.error = "bad url: " + url;
        return resp;
    }

    if (body && !parts.https) {
        auto merged = defaultHeaders_;
        for (const auto& kv : headers) merged[kv.first] = kv.second;
        return httpRawRequest("POST", wideToUtf8(parts.host), parts.port, wideToUtf8(parts.path),
                              merged, body, timeouts_[1], timeouts_[3], onStart);
    }

    HINTERNET connect = WinHttpConnect(static_cast<HINTERNET>(session_), parts.host.c_str(),
                                       parts.port, 0);
    if (!connect) {
        resp.error = "connect failed: " + url;
        return resp;
    }

    DWORD flags = parts.https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, utf8ToWide(method).c_str(),
                                           parts.path.c_str(), nullptr,
                                           WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    WinHttpCloseHandle(connect);
    if (!request) {
        resp.error = "open request failed: " + url;
        return resp;
    }

    if (parts.https) {
        DWORD sec = 0;
        if (!WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec))) {
            DWORD e = GetLastError();
            WinHttpCloseHandle(request);
            resp.error = "security options failed (" + std::to_string(e) + "): " + url;
            return resp;
        }
    }

    WinHttpSetTimeouts(request, timeouts_[0], timeouts_[1], timeouts_[2], timeouts_[3]);

    std::wstring headerStr;
    auto merged = defaultHeaders_;
    for (auto& kv : headers) merged[kv.first] = kv.second;
    for (auto& kv : merged) {
        headerStr += utf8ToWide(kv.first + ": " + kv.second + "\r\n");
    }

    LPCVOID bodyPtr = body ? body->data() : WINHTTP_NO_REQUEST_DATA;
    DWORD bodyLen = body ? static_cast<DWORD>(body->size()) : 0;

    BOOL sent = WinHttpSendRequest(request,
                                   headerStr.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headerStr.c_str(),
                                   headerStr.empty() ? 0 : (DWORD)-1,
                                   const_cast<LPVOID>(bodyPtr), bodyLen, bodyLen, 0);
    if (!sent) {
        DWORD e = GetLastError();
        WinHttpCloseHandle(request);
        resp.error = "send failed (" + std::to_string(e) + "): " + url;
        return resp;
    }

    if (!WinHttpReceiveResponse(request, nullptr)) {
        DWORD e = GetLastError();
        WinHttpCloseHandle(request);
        resp.error = "receive failed (" + std::to_string(e) + "): " + url;
        return resp;
    }

    DWORD status = 0, size = sizeof(status);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX);
    resp.status = static_cast<int>(status);

    {
        DWORD clen = 0, csize = sizeof(clen);
        if (WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &clen, &csize, WINHTTP_NO_HEADER_INDEX)) {
            resp.contentLength = clen;
            if (onStart) onStart(static_cast<size_t>(clen));
        }
    }

    std::vector<uint8_t> chunk;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(request, &avail)) {
            DWORD e = GetLastError();
            resp.error = "read failed (" + std::to_string(e) + "): " + url;
            break;
        }
        if (avail == 0) break;
        if (avail > chunk.size()) chunk.resize(avail);
        DWORD read = 0;
        if (!WinHttpReadData(request, chunk.data(), avail, &read)) {
            DWORD e = GetLastError();
            resp.error = "read failed (" + std::to_string(e) + "): " + url;
            break;
        }
        if (read > kMaxChunkedResponseBytes - resp.body.size()) {
            resp.error = "response too large: " + url;
            break;
        }
        resp.body.insert(resp.body.end(), chunk.begin(), chunk.begin() + read);
        if (onProgress && read) onProgress(read);
    }

    if (resp.error.empty() && resp.status >= 200 && resp.status < 300 &&
        resp.status != 204 && resp.status != 304 && resp.contentLength != 0 &&
        resp.body.size() < resp.contentLength) {
        resp.error = "truncated response (" + std::to_string(resp.body.size()) + " of " +
                     std::to_string(resp.contentLength) + " bytes): " + url;
    }

    WinHttpCloseHandle(request);
    return resp;
}

HttpResponse HttpClient::postForm(const std::string& url, const std::string& formBody,
                                  const std::map<std::string, std::string>& headers) {
    std::map<std::string, std::string> h = headers;
    h["Content-Type"] = "application/x-www-form-urlencoded";
    std::vector<uint8_t> body(formBody.begin(), formBody.end());
    return request("POST", url, &body, h, nullptr, nullptr);
}

HttpResponse HttpClient::get(const std::string& url, const std::map<std::string, std::string>& headers,
                             const ByteProgress& onProgress, const SizeCallback& onStart) {
    return request("GET", url, nullptr, headers, onProgress, onStart);
}

HttpResponse HttpClient::plainGetRaw(const std::string& url,
                                     const std::map<std::string, std::string>& headers,
                                     int connectMs, int recvMs) {
    HttpResponse resp;
    UrlParts parts;
    if (!parseUrl(url, parts)) {
        resp.error = "bad url: " + url;
        return resp;
    }
    if (parts.https) {
        resp.error = "plainGetRaw requires a plain http url: " + url;
        return resp;
    }
    return httpRawRequest("GET", wideToUtf8(parts.host), parts.port, wideToUtf8(parts.path),
                          headers, nullptr, connectMs, recvMs, nullptr);
}

} // namespace fivem