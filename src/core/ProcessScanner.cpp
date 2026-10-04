#include "ProcessScanner.h"
#include "Logger.h"
#include "../utils/Str.h"
#include "../utils/Json.h"
#include <windows.h>
#include <tlhelp32.h>
#include <atomic>
#include <fstream>
#include <limits>
#include <sstream>
#include <mutex>
#include <thread>
#include <vector>
#include <set>
#include <map>
#include <cctype>
namespace fivem {
namespace {
std::string wideToUtf8(const wchar_t* w) {
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string s(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), len, nullptr, nullptr);
    return s;
}
const uint8_t* findBytes(const uint8_t* data, size_t len, const uint8_t* pat, size_t patLen) {
    if (patLen > len) return nullptr;
    for (size_t i = 0; i + patLen <= len; ++i) {
        size_t j = 0;
        while (j < patLen && data[i + j] == pat[j]) ++j;
        if (j == patLen) return data + i;
    }
    return nullptr;
}
size_t matchIpPort(const uint8_t* p, const uint8_t* end) {
    auto readNum = [&](const uint8_t*& c, int maxLen) -> int {
        int v = 0, n = 0;
        while (c < end && n < maxLen && *c >= '0' && *c <= '9') { v = v * 10 + (*c - '0'); ++c; ++n; }
        if (n == 0) return -1;
        return v;
    };
    const uint8_t* c = p;
    int a[4];
    for (int i = 0; i < 4; ++i) {
        a[i] = readNum(c, 3);
        if (a[i] < 0 || a[i] > 255) return 0;
        if (i < 3) { if (c >= end || *c != '.') return 0; ++c; }
    }
    if (c >= end || *c != ':') return 0;
    ++c;
    int port = readNum(c, 5);
    if (port < 1 || port > 65535) return 0;
    return static_cast<size_t>(c - p);
}
struct ScanConfig {
    size_t minRegionSize = 1;
    size_t maxRegionSize = 64ull * 1024 * 1024;
    size_t maxRegions = std::numeric_limits<size_t>::max();
    bool reportRegionLimit = false;
};
template <typename Hit>
bool scanForPattern(const std::vector<ProcessInfo>& procs, const uint8_t* pat, size_t patLen,
                    const ScanConfig& cfg, Hit hit) {
    std::atomic<bool> stop{false};
    std::mutex mtx;
    bool found = false;
    std::vector<std::thread> threads;
    for (auto& pi : procs) {
        threads.emplace_back([&, pi]() {
            if (stop.load()) return;
            HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pi.pid);
            if (!h) return;
            MEMORY_BASIC_INFORMATION mbi;
            uintptr_t addr = 0;
            size_t regions = 0;
            bool limitReached = false;
            while (!stop.load()) {
                if (!VirtualQueryEx(h, reinterpret_cast<void*>(addr), &mbi, sizeof(mbi))) break;
                ++regions;
                if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) &&
                    (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY)) &&
                    mbi.RegionSize >= cfg.minRegionSize && mbi.RegionSize <= cfg.maxRegionSize) {
                    std::vector<uint8_t> buf(mbi.RegionSize);
                    SIZE_T read = 0;
                    if (ReadProcessMemory(h, mbi.BaseAddress, buf.data(), mbi.RegionSize, &read)) {
                        const uint8_t* p = buf.data();
                        const uint8_t* e = buf.data() + read;
                        size_t pos = 0;
                        while (pos + patLen <= read) {
                            const uint8_t* hp = findBytes(buf.data() + pos, read - pos, pat, patLen);
                            if (!hp) break;
                            {
                                std::lock_guard<std::mutex> lock(mtx);
                                if (!stop.load()) {
                                    hit(buf.data(), static_cast<size_t>(hp - buf.data()), read);
                                    stop.store(true);
                                    found = true;
                                    CloseHandle(h);
                                    return;
                                }
                            }
                            break;
                        }
                        (void)p; (void)e;
                    }
                }
                if (regions >= cfg.maxRegions) { limitReached = true; break; }
                uintptr_t next = addr + mbi.RegionSize;
                if (next <= addr) break;
                addr = next;
            }
            if (limitReached && cfg.reportRegionLimit) {
                std::lock_guard<std::mutex> lock(mtx);
                LOG("Elertuk a maximalis terulet-szamot (" + std::to_string(regions) +
                    "), lepunk. (PID " + std::to_string(pi.pid) + ")", LogLevel::INFO);
            }
            CloseHandle(h);
        });
    }
    for (auto& t : threads) t.join();
    return found;
}
}
std::vector<ProcessInfo> getFiveMProcesses() {
    std::vector<ProcessInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            std::string name = wideToUtf8(pe.szExeFile);
            if (startsWith(toLower(name), "fivem")) {
                out.push_back({pe.th32ProcessID, name});
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}
std::vector<ProcessInfo> getGtaProcesses() {
    std::vector<ProcessInfo> out;
    for (auto& p : getFiveMProcesses()) {
        std::string lower = toLower(p.name);
        if (lower.find("_gtaprocess") != std::string::npos) out.push_back(p);
    }
    return out;
}
std::string findFiveMToken() {
    LOG("FiveM GTAProcess folyamatok keresese...", LogLevel::INFO);
    auto gta = getGtaProcesses();
    if (gta.empty()) {
        LOG("Egyetlen FiveM GTAProcess sem fut.", LogLevel::ERROR);
        return "";
    }
    for (auto& p : gta) {
        LOG("  - " + p.name + " (PID: " + std::to_string(p.pid) + ")", LogLevel::INFO);
    }
    static const std::string marker = "X-CitizenFX-Token: ";
    std::string token;
    ScanConfig cfg;
    cfg.minRegionSize = 1;
    cfg.maxRegionSize = 67ull * 1024 * 1024;
    cfg.maxRegions = std::numeric_limits<size_t>::max();
    bool ok = scanForPattern(gta, reinterpret_cast<const uint8_t*>(marker.data()), marker.size(),
                             cfg, [&](const uint8_t* base, size_t off, size_t total) {
                                 size_t p = off + marker.size();
                                 size_t end = p;
                                 size_t cap = std::min(total, p + 2000);
                                 while (end < cap && base[end] != '\0' && base[end] != '\r' &&
                                        base[end] != '\n') ++end;
                                 token.assign(reinterpret_cast<const char*>(base + p),
                                              reinterpret_cast<const char*>(base + end));
                             });
    if (!ok || token.empty()) {
        LOG("Token nem talalhato.", LogLevel::ERROR);
        return "";
    }
    LOG("Token megtalalva!", LogLevel::SUCCESS);
    return token;
}
std::vector<std::string> findIpsInMemory() {
    LOG("Scanning GTAProcess processes for all IPs...", LogLevel::INFO);
    auto gta = getGtaProcesses();
    if (gta.empty()) return {};
    std::set<std::string> ips;
    std::mutex mtx;
    ScanConfig cfg;
    cfg.minRegionSize = 1000;
    cfg.maxRegionSize = 64ull * 1024 * 1024;
    cfg.maxRegions = 2000;
    cfg.reportRegionLimit = true;
    std::vector<std::thread> threads;
    for (auto& pi : gta) {
        threads.emplace_back([&, pi]() {
            HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pi.pid);
            if (!h) return;
            MEMORY_BASIC_INFORMATION mbi;
            uintptr_t addr = 0;
            size_t regions = 0;
            while (true) {
                if (!VirtualQueryEx(h, reinterpret_cast<void*>(addr), &mbi, sizeof(mbi))) break;
                ++regions;
                if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) &&
                    (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY)) &&
                    mbi.RegionSize >= cfg.minRegionSize && mbi.RegionSize <= cfg.maxRegionSize) {
                    std::vector<uint8_t> buf(mbi.RegionSize);
                    SIZE_T read = 0;
                    if (ReadProcessMemory(h, mbi.BaseAddress, buf.data(), mbi.RegionSize, &read)) {
                        std::vector<std::string> local;
                        const uint8_t* p = buf.data();
                        const uint8_t* end = buf.data() + read;
                        while (p < end) {
                            if (*p >= '0' && *p <= '9') {
                                size_t consumed = matchIpPort(p, end);
                                if (consumed > 0) {
                                    local.emplace_back(reinterpret_cast<const char*>(p), consumed);
                                    p += consumed;
                                    continue;
                                }
                            }
                            ++p;
                        }
                        if (!local.empty()) {
                            std::lock_guard<std::mutex> lock(mtx);
                            ips.insert(local.begin(), local.end());
                        }
                    }
                }
                if (regions >= cfg.maxRegions) {
                    std::lock_guard<std::mutex> lock(mtx);
                    LOG("Elertuk a maximalis terulet-szamot (" + std::to_string(regions) +
                        "), lepunk.", LogLevel::INFO);
                    break;
                }
                uintptr_t next = addr + mbi.RegionSize;
                if (next <= addr) break;
                addr = next;
            }
            CloseHandle(h);
        });
    }
    for (auto& t : threads) t.join();
    return std::vector<std::string>(ips.begin(), ips.end());
}
static const char* kNameFile = "server_name.txt";
static std::map<std::string, std::string> loadNameMap() {
    std::map<std::string, std::string> out;
    auto data = readFileBytes(kNameFile);
    if (!data) return out;
    try {
        Json js = Json::parse(std::string(data->begin(), data->end()));
        for (auto& kv : js.items()) out[kv.first] = kv.second.asString();
    } catch (...) {}
    return out;
}
void saveServerName(const std::string& ip, const std::string& name) {
    if (ip.empty() || name.empty()) return;
    auto m = loadNameMap();
    m[ip] = name;
    std::ostringstream ss;
    ss << "{\n";
    bool first = true;
    for (auto& kv : m) {
        if (!first) ss << ",\n";
        first = false;
        ss << "  \"" << kv.first << "\": \"" << kv.second << "\"";
    }
    ss << "\n}\n";
    writeTextFile(kNameFile, ss.str());
}
std::string getCachedServerName(const std::string& ip) {
    auto m = loadNameMap();
    auto it = m.find(ip);
    return it == m.end() ? "" : it->second;
}
}
