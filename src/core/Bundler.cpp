#include "Bundler.h"
#include "Logger.h"
#include "../crypto/Sha256.h"
#include <windows.h>
#include <filesystem>
#include <mutex>
#include <vector>
#include <fstream>
namespace fs = std::filesystem;
namespace fivem {
namespace {
struct PayloadItem {
    const char* name;
    int id;
    unsigned long long size;
    const char* sha256;
};
#include "payload_manifest_gen.h"
const PayloadItem kItems[] = FIVEM_PAYLOAD_ITEMS;
std::wstring g_rootW;
std::string g_rootU8;
std::once_flag g_initOnce;
bool g_ready = false;
std::string g_lastErr;
std::wstring toWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}
std::string toUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}
std::wstring localAppDataDir() {
    wchar_t buf[4096];
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, 4096);
    if (n > 0 && n < 4096) return buf;
    n = GetEnvironmentVariableW(L"USERPROFILE", buf, 4096);
    if (n > 0 && n < 4096) return std::wstring(buf) + L"\\AppData\\Local";
    return L"";
}
bool itemVerified(const std::wstring& root, const PayloadItem& it) {
    fs::path p = fs::path(root) / fs::path(toWide(it.name));
    std::error_code ec;
    if (!fs::is_regular_file(p, ec)) return false;
    if (fs::file_size(p, ec) != (uintmax_t)it.size) return false;
    std::ifstream f(p, std::ios::binary);
    if (!f) return false;
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return sha256Hex(data) == it.sha256;
}
bool extractItem(const std::wstring& root, const PayloadItem& it, std::string& err) {
    HMODULE mod = GetModuleHandleW(nullptr);
    HRSRC rs = FindResourceW(mod, MAKEINTRESOURCEW(it.id), MAKEINTRESOURCEW(RT_RCDATA));
    if (!rs) { err = std::string("resource id ") + std::to_string(it.id) + " (" + it.name + ") missing"; return false; }
    HGLOBAL hg = LoadResource(mod, rs);
    DWORD sz = SizeofResource(mod, rs);
    const void* data = LockResource(hg);
    if (!hg || !data || sz == 0 || sz != (DWORD)it.size) {
        err = std::string("resource size mismatch: ") + it.name;
        return false;
    }
    fs::path dest = fs::path(root) / fs::path(toWide(it.name));
    std::error_code ec;
    fs::create_directories(dest.parent_path(), ec);
    if (ec) { err = "create_directories failed: " + ec.message(); return false; }
    fs::path tmp = dest;
    tmp += L".tmp-" + std::to_wstring(GetCurrentProcessId());
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { err = "CreateFileW failed"; return false; }
    bool ok = true;
    const BYTE* p = static_cast<const BYTE*>(data);
    DWORD left = sz;
    while (left > 0) {
        DWORD written = 0;
        if (!WriteFile(h, p, left, &written, nullptr) || written == 0) { ok = false; break; }
        p += written;
        left -= written;
    }
    FlushFileBuffers(h);
    CloseHandle(h);
    if (!ok) { DeleteFileW(tmp.c_str()); err = "WriteFile failed"; return false; }
    for (int attempt = 0; attempt < 5; ++attempt) {
        if (MoveFileExW(tmp.c_str(), dest.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            return true;
        if (GetLastError() != ERROR_ACCESS_DENIED) break;
        Sleep(400);
    }
    err = "MoveFileExW failed";
    DeleteFileW(tmp.c_str());
    return false;
}
void doInit() {
    std::string& err = g_lastErr;
    auto wroot = localAppDataDir();
    if (wroot.empty()) { err = "LOCALAPPDATA not resolvable"; return; }
    std::wstring root = wroot + L"\\FiveMDumper\\payload";
    HANDLE mtx = CreateMutexW(nullptr, FALSE, L"Local\\FiveMDumper-Payload");
    if (!mtx) { err = "CreateMutexW failed"; return; }
    DWORD wait = WaitForSingleObject(mtx, 60000);
    if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
        CloseHandle(mtx);
        err = "payload mutex timeout";
        return;
    }
    bool stale = false;
    for (const auto& it : kItems)
        if (!itemVerified(root, it)) { stale = true; break; }
    if (stale) {
        for (const auto& it : kItems) {
            if (!extractItem(root, it, err)) {
                ReleaseMutex(mtx);
                CloseHandle(mtx);
                return;
            }
        }
        LOG("Embedded payload extracted to " + toUtf8(root), LogLevel::INFO);
    }
    ReleaseMutex(mtx);
    CloseHandle(mtx);
    g_rootW = std::move(root);
    g_rootU8 = toUtf8(g_rootW);
    g_ready = true;
}
}
bool ensurePayload(std::string& errOut) {
    std::call_once(g_initOnce, doInit);
    if (!g_ready) { errOut = g_lastErr; return false; }
    return true;
}
std::string payloadRoot() {
    return g_ready ? g_rootU8 : "";
}
}
