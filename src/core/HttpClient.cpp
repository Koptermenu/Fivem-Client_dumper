#include "HttpClient.h"

#include <windows.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cctype>
#include <chrono>
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

bool parseUrl(const std::string& url, UrlParts& parts) {
    std::string s = url;
    if (s.rfind("https://", 0) == 0) {
        parts.https = true;
        s = s.substr(8);
        parts.port = INTERNET_DEFAULT_HTTPS_PORT;
    } else if (s.rfind("http://", 0) == 0) {
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
        parts.port = static_cast<INTERNET_PORT>(std::stoi(hostport.substr(colon + 1)));
    }
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

// Plain-HTTP GET/POST over raw Winsock, written as ONE TCP segment with hard
// connect/receive deadlines. Some (older/custom) FXServer builds never answer
// when the request body arrives in a separate segment from the headers, which
// is what WinHTTP always does; WinHTTP also retries TCP connect internally and
// can overshoot any configured timeout by ~20s on blackholed IPs.
HttpResponse httpRawRequest(const std::string& method, const std::string& host, INTERNET_PORT port,
                            const std::string& path, const std::map<std::string, std::string>& headers,
                            const std::vector<uint8_t>* body, int connectMs, int recvMs) {
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
        long connectRemain = static_cast<long>(connectMs) -
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

    // connectMs and recvMs are phases of ONE total deadline.
    auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now() - started).count();
    long remain = static_cast<long>(recvMs) - static_cast<long>(elapsedMs);
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
        contentLen = static_cast<size_t>(std::strtoull(head.c_str() + p + 15, nullptr, 10));
        haveLen = true;
    }

    std::string payload = buf.substr(hdrEnd);
    if (chunked) {
        std::string out;
        size_t pos = 0;
        for (;;) {
            size_t eol;
            while ((eol = payload.find("\r\n", pos)) == std::string::npos)
                if (pull(payload) <= 0) return fail("chunked stream truncated");
            size_t csz = static_cast<size_t>(std::strtoul(payload.c_str() + pos, nullptr, 16));
            pos = eol + 2;
            if (csz == 0) break;
            while (payload.size() < pos + csz + 2)
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
                break;
            }
        }
    } else {
        while (pull(payload) > 0) {}
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
                                 const ByteProgress& onProgress) {
    HttpResponse resp;
    UrlParts parts;
    if (!parseUrl(url, parts)) {
        resp.error = "bad url: " + url;
        return resp;
    }

    // Plain HTTP requests with a body (the /client POST) go through raw Winsock
    // so headers and body arrive in one TCP segment; WinHTTP splits them and
    // some FXServer builds then never respond.
    if (body && !parts.https) {
        auto merged = defaultHeaders_;
        for (const auto& kv : headers) merged[kv.first] = kv.second;
        return httpRawRequest("POST", wideToUtf8(parts.host), parts.port, wideToUtf8(parts.path),
                              merged, body, timeouts_[1], timeouts_[3]);
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
        DWORD sec = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));
    }

    DWORD timeouts[] = {15000, 30000, 30000, 30000};
    WinHttpSetTimeouts(request, timeouts[0], timeouts[1], timeouts[2], timeouts[3]);

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

    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(request, &avail)) break;
        if (avail == 0) break;
        std::vector<uint8_t> chunk(avail);
        DWORD read = 0;
        if (!WinHttpReadData(request, chunk.data(), avail, &read)) break;
        chunk.resize(read);
        resp.body.insert(resp.body.end(), chunk.begin(), chunk.end());
        if (onProgress && read) onProgress(read);
    }

    WinHttpCloseHandle(request);
    return resp;
}

HttpResponse HttpClient::postForm(const std::string& url, const std::string& formBody,
                                  const std::map<std::string, std::string>& headers) {
    std::map<std::string, std::string> h = headers;
    h["Content-Type"] = "application/x-www-form-urlencoded";
    std::vector<uint8_t> body(formBody.begin(), formBody.end());
    return request("POST", url, &body, h, nullptr);
}

HttpResponse HttpClient::get(const std::string& url, const std::map<std::string, std::string>& headers,
                             const ByteProgress& onProgress) {
    return request("GET", url, nullptr, headers, onProgress);
}

HttpResponse HttpClient::plainGetRaw(const std::string& url,
                                     const std::map<std::string, std::string>& headers,
                                     int connectMs, int recvMs) {
    HttpResponse resp;
    UrlParts parts;
    if (!parseUrl(url, parts) || parts.https) {
        resp.error = "plainGetRaw requires a plain http url: " + url;
        return resp;
    }
    return httpRawRequest("GET", wideToUtf8(parts.host), parts.port, wideToUtf8(parts.path),
                          headers, nullptr, connectMs, recvMs);
}

} // namespace fivem
