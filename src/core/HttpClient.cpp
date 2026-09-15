#include "HttpClient.h"

#include <windows.h>
#include <winhttp.h>
#include <cstring>

#pragma comment(lib, "winhttp.lib")

namespace fivem {

namespace {

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
                                 const std::map<std::string, std::string>& headers) {
    HttpResponse resp;
    UrlParts parts;
    if (!parseUrl(url, parts)) {
        resp.error = "bad url: " + url;
        return resp;
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
    }

    WinHttpCloseHandle(request);
    return resp;
}

HttpResponse HttpClient::postForm(const std::string& url, const std::string& formBody,
                                  const std::map<std::string, std::string>& headers) {
    std::map<std::string, std::string> h = headers;
    h["Content-Type"] = "application/x-www-form-urlencoded";
    std::vector<uint8_t> body(formBody.begin(), formBody.end());
    return request("POST", url, &body, h);
}

HttpResponse HttpClient::get(const std::string& url, const std::map<std::string, std::string>& headers) {
    return request("GET", url, nullptr, headers);
}

} // namespace fivem
