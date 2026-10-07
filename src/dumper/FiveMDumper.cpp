#include "FiveMDumper.h"
#include "../core/Logger.h"
#include "../crypto/Sha256.h"
#include "../crypto/ChaCha20.h"
#include "../utils/Str.h"
#include "../utils/Term.h"
#include "../utils/Json.h"
#include "../utils/ProgressBar.h"
#include <windows.h>
#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>
#include <ctime>
namespace fs = std::filesystem;
namespace fivem {
static bool isSafeRelPath(const std::string& rel) {
    if (rel.empty()) return false;
    if (rel.front() == '/' || rel.front() == '\\') return false;
    if (rel.find(':') != std::string::npos) return false;
    for (char c : rel)
        if (static_cast<unsigned char>(c) < 0x20 || c == '<' || c == '>' || c == '"' ||
            c == '|' || c == '?' || c == '*')
            return false;
    size_t start = 0;
    for (;;) {
        size_t end = rel.find_first_of("/\\", start);
        if (rel.compare(start, end == std::string::npos ? std::string::npos : end - start, "..") == 0)
            return false;
        if (end == std::string::npos) break;
        start = end + 1;
    }
    if ((rel.back() == '.' || rel.back() == ' ') &&
        rel.find_first_not_of('.') != std::string::npos)
        return false;
    return true;
}
static bool parseDigits(const std::string& s, unsigned long long& out) {
    if (s.empty() || s.size() > 18) return false;
    unsigned long long v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + static_cast<unsigned long long>(c - '0');
    }
    out = v;
    return true;
}
static std::string truncateForPath(const std::string& s, size_t maxBytes) {
    std::string out = s;
    if (s.size() > maxBytes) {
        size_t i = 0, lastGood = 0;
        while (i < s.size() && i < maxBytes) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            size_t len;
            if ((c & 0x80) == 0x00) len = 1;
            else if ((c & 0xE0) == 0xC0) len = 2;
            else if ((c & 0xF0) == 0xE0) len = 3;
            else if ((c & 0xF8) == 0xF0) len = 4;
            else { ++i; continue; }
            if (i + len > maxBytes) break;
            i += len;
            lastGood = i;
        }
        out = s.substr(0, lastGood);
    }
    while (!out.empty() && (out.back() == '.' || out.back() == ' '))
        out.pop_back();
    return out;
}
FiveMDumper::FiveMDumper(std::string baseUrl, std::string token,
                         std::string serverName, Checkpoint& checkpoint)
    : baseUrl_(std::move(baseUrl)), token_(std::move(token)),
      serverName_(std::move(serverName)), checkpoint_(checkpoint) {
    if (!token_.empty()) http_.setHeader("X-CitizenFX-Token", token_);
    http_.setHeader("User-Agent", "CitizenFX/1");
    if (const char* w = getenv("DUMPER_WORKERS")) {
        int v = atoi(w);
        if (v >= 1 && v <= 64) maxWorkers_ = v;
    }
    setServerName(serverName_);
}
void FiveMDumper::setServerName(const std::string& name) {
    serverName_ = name;
    std::string safe = safeName(name.empty() ? baseUrl_ : name);
    safe = truncateForPath(safe, 80);
    serverDir = safe.empty() ? "server" : safe;
    resourcesDir = "Servers/" + serverDir + "/Resources";
    unpackedDir = "Servers/" + serverDir + "/Unpacked";
    tempDir = "Servers/" + serverDir + "/Temp";
    if (configFetched_ && !grants_.empty()) {
        writeTextFile(resourcesDir + "/Grants.txt", grants_);
    }
}
bool FiveMDumper::applyConfiguration(const Json& js) {
    grants_ = js.strAt("grants_token", "");
    hostname_.clear();
    for (const char* key : {"hostname", "serverName", "name"}) {
        std::string v = js.strAt(key, "");
        if (!v.empty()) { hostname_ = v; break; }
    }
    checkpoint_.server_ip = baseUrl_.size() > 7 ? baseUrl_.substr(
        (startsWith(baseUrl_, "https://") ? 8 : 7)) : baseUrl_;
    checkpoint_.save();
    configFetched_ = true;
    resources_.clear();
    const Json& res = js.at("resources");
    if (res.isArray()) {
        for (const auto& r : res.arr()) {
            if (!r.isObject()) continue;
            ResourceInfo info;
            info.name = r.strAt("name");
            info.uri = r.strAt("uri");
            info.fileServer = r.strAt("fileServer");
            const Json& files = r.at("files");
            if (files.isObject()) {
                for (auto& kv : files.items()) info.files.push_back({kv.first, kv.second.asString()});
            }
            const Json& streams = r.at("streamFiles");
            if (streams.isObject()) {
                for (auto& kv : streams.items()) {
                    std::string h;
                    if (kv.second.isObject() && kv.second.at("hash").isString())
                        h = kv.second.at("hash").asString();
                    info.streamFiles.push_back({kv.first, h});
                }
            }
            if (!info.name.empty()) resources_.push_back(std::move(info));
        }
    }
    LOG("Configuration applied: " + std::to_string(resources_.size()) + " resources", LogLevel::INFO);
    return !resources_.empty();
}

bool FiveMDumper::getConfiguration() {
    if (configFetched_) return true;
    auto resp = http_.postForm(baseUrl_ + "/client", "method=getConfiguration");
    if (resp.ok()) {
        Json js;
        const std::string body(resp.body.begin(), resp.body.end());
        bool parsed = false;
        try {
            js = Json::parse(body);
            parsed = true;
        } catch (const std::exception& e) {
            LOG(std::string("JSON parse error: ") + e.what(), LogLevel::ERROR);
        }
        if (parsed) {
            if (js.has("error") && js.at("error").isString() && !js.has("resources")) {
                LOG("Server rejected the token: " + js.at("error").asString() +
                    " - connect in FiveM to this exact server first.", LogLevel::ERROR);
            } else if (applyConfiguration(js)) {
                rawConfig_ = body;
                uploadToServerStore();
                return true;
            }
        }
    } else {
        LOG("getConfiguration failed: " + resp.error + " (status " + std::to_string(resp.status) + ")",
            LogLevel::ERROR);
    }
    if (fetchFromServerStore()) return true;
    return false;
}

std::string FiveMDumper::serverStoreUrl() const {
    if (const char* env = getenv("DUMPER_STORE_URL")) {
        std::string v = trim(env);
        if (v.empty() || v == "off") return "";
        while (!v.empty() && v.back() == '/') v.pop_back();
        return v;
    }
    return "https://grantsclk.ckcloud.de5.net";
}

std::string FiveMDumper::serverStoreKey() const { return safeName(baseUrl_); }

bool FiveMDumper::fetchFromServerStore() {
    const std::string root = serverStoreUrl();
    if (root.empty()) return false;
    const std::string url = root + "/v1/servers/" + serverStoreKey();
    HttpResponse resp = http_.get(url);
    if (!resp.ok()) {
        LOG("Server store lookup failed for " + serverStoreKey() + ": " +
            (resp.error.empty() ? "status " + std::to_string(resp.status) : resp.error),
            LogLevel::INFO);
        return false;
    }
    Json js;
    const std::string body(resp.body.begin(), resp.body.end());
    try {
        js = Json::parse(body);
    } catch (const std::exception& e) {
        LOG("Server store response parse error: " + std::string(e.what()), LogLevel::WARNING);
        return false;
    }
    if (!applyConfiguration(js)) {
        LOG("Server store response has no usable configuration.", LogLevel::INFO);
        return false;
    }
    if (js.has("storeSavedAt")) {
        const double saved = js.at("storeSavedAt").asNumber();
        const long long ageHours =
            static_cast<long long>((static_cast<double>(time(nullptr)) * 1000.0 - saved) / 3600000.0);
        if (saved > 0 && ageHours >= 24) {
            LOG("Stored configuration is about " + std::to_string(ageHours) +
                    " hours old; resources added to the server since then are not in it. "
                    "Connect once with the game to refresh the store.",
                LogLevel::WARNING);
            std::cout << CLR(term::YELLOW) << "[!]" << CLR(term::RESET)
                      << " A tarolt konfiguracio ~" << ageHours
                      << " oras: az utana felrakott uj resource-ok nincsenek benne. Egy "
                         "friss, jogos csatlakozasos dump frissiti a tarat.\n";
        }
    }
    usingCachedConfig_ = true;
    rawConfig_ = body;
    LOG("Configuration fetched from the central server store.", LogLevel::INFO);
    std::cout << CLR(term::GREEN) << "[+]" << CLR(term::RESET)
              << " A konfiguracio a kozponti tarbol jon (" << serverStoreKey()
              << ") - jatek-csatlakozas nelkul is mukodik.\n";
    return true;
}

void FiveMDumper::uploadToServerStore() {
    const std::string root = serverStoreUrl();
    if (root.empty() || rawConfig_.empty()) return;
    HttpResponse resp = http_.postJson(root + "/v1/servers/" + serverStoreKey(), rawConfig_);
    if (resp.ok()) {
        LOG("Configuration uploaded to the central server store: " + serverStoreKey(),
            LogLevel::INFO);
    } else {
        LOG("Configuration upload to the central store failed: " +
                (resp.error.empty() ? "status " + std::to_string(resp.status) : resp.error),
            LogLevel::WARNING);
    }
}

void FiveMDumper::saveConfigCache() {
    if (rawConfig_.empty() || serverDir.empty()) return;
    writeTextFile("Servers/" + serverDir + "/config.json", rawConfig_);
    writeTextFile("Servers/" + serverDir + "/config_ip.txt", baseUrl_);
}

bool FiveMDumper::findCachedConfig(const std::string& baseUrl, std::string& outDir) {
    std::error_code ec;
    for (auto& e : fs::directory_iterator("Servers", ec)) {
        if (!e.is_directory(ec)) continue;
        auto ip = readFileBytes((e.path() / "config_ip.txt").string());
        if (!ip) continue;
        std::string stored(ip->begin(), ip->end());
        if (trim(stored) != baseUrl) continue;
        if (!fs::exists(e.path() / "config.json", ec)) continue;
        outDir = e.path().filename().string();
        return true;
    }
    return false;
}

bool FiveMDumper::loadConfigFile(const std::string& path) {
    if (configFetched_) return true;
    auto data = readFileBytes(path);
    if (!data) return false;
    Json js;
    try {
        js = Json::parse(std::string(data->begin(), data->end()));
    } catch (const std::exception& e) {
        LOG("Config file parse error (" + path + "): " + std::string(e.what()), LogLevel::WARNING);
        return false;
    }
    if (!applyConfiguration(js)) return false;
    usingCachedConfig_ = true;
    rawConfig_ = std::string(data->begin(), data->end());
    LOG("Configuration loaded from file: " + path, LogLevel::INFO);
    return true;
}

bool FiveMDumper::loadCachedConfiguration() {
    return loadConfigFile("Servers/" + serverDir + "/config.json");
}
static std::string stripFxColors(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '^' && i + 1 < s.size()) {
            char n = s[i + 1];
            if (n >= '0' && n <= '9') { ++i; continue; }
            if (n == 's') { ++i; continue; }
            if (n == '^') { ++i; out += '^'; continue; }
        }
        out += s[i];
    }
    return out;
}
static std::string cleanDynamicHostname(const std::string& raw) {
    std::string name = trim(stripFxColors(raw));
    if (name.empty() || iequals(name, "default FXServer") ||
        iequals(name, "FXServer, but unconfigured"))
        return "";
    return name;
}
std::string FiveMDumper::probeDynamicHostname(const std::string& baseUrl, int timeoutMs) {
    auto resp = HttpClient::plainGetRaw(baseUrl + "/dynamic.json", {{"User-Agent", "CitizenFX/1"}},
                                        timeoutMs, timeoutMs);
    if (!resp.ok()) return "";
    try {
        Json js = Json::parse(std::string(resp.body.begin(), resp.body.end()));
        return cleanDynamicHostname(js.strAt("hostname", ""));
    } catch (const std::exception&) {
        return "";
    }
}
bool FiveMDumper::fetchDynamicHostname() {
    auto resp = http_.get(baseUrl_ + "/dynamic.json");
    if (!resp.ok()) {
        LOG("dynamic.json fetch failed: " + resp.error + " (status " + std::to_string(resp.status) + ")",
            LogLevel::WARNING);
        return false;
    }
    Json js;
    try {
        js = Json::parse(std::string(resp.body.begin(), resp.body.end()));
    } catch (const std::exception& e) {
        LOG(std::string("dynamic.json parse error: ") + e.what(), LogLevel::WARNING);
        return false;
    }
    std::string name = cleanDynamicHostname(js.strAt("hostname", ""));
    if (name.empty()) {
        LOG("dynamic.json: no usable hostname in response", LogLevel::WARNING);
        return false;
    }
    hostname_ = name;
    return true;
}
void FiveMDumper::downloadAndDecrypt(const std::string& url, const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& iv, const std::string& outPath,
                                     const std::string& expectedChecksum,
                                     const ByteProgress& onBytes,
                                     const SizeCallback& onStart) {
    static const int maxRetries = 5;
    HttpResponse resp;
    for (int attempt = 0; attempt < maxRetries; ++attempt) {
        SizeCallback firstAttempt = (attempt == 0) ? onStart : SizeCallback();
        resp = http_.get(url, {}, onBytes, firstAttempt);
        if (resp.ok()) break;
        if (attempt < maxRetries - 1) {
            LOG("Download retry " + std::to_string(attempt + 1) + "/" + std::to_string(maxRetries) +
                " for " + outPath + ": " + resp.error, LogLevel::WARNING);
            std::this_thread::sleep_for(std::chrono::seconds(2 << attempt));
        } else {
            LOG("Download failed after " + std::to_string(maxRetries) + " attempts for " +
                outPath + ": " + resp.error, LogLevel::WARNING);
        }
    }
    if (!resp.ok()) {
        throw std::runtime_error("Failed to download " + outPath + ": " + resp.error);
    }
    std::vector<uint8_t> dec;
    bool decrypted = false;
    for (int nonceLen = 12; nonceLen >= 8; nonceLen -= 4) {
        if ((int)iv.size() < nonceLen) continue;
        std::vector<uint8_t> nonce(iv.begin(), iv.begin() + nonceLen);
        try {
            dec = chacha20Xor(key, nonce, resp.body);
            decrypted = true;
            break;
        } catch (...) { decrypted = false; }
    }
    if (!decrypted) throw std::runtime_error("ChaCha20 decrypt failed: " + outPath);
    if (endsWith(toLower(outPath), ".rpf") && dec.size() < 3) {
        throw std::runtime_error("Invalid RPF header for " + outPath);
    }
    if (endsWith(toLower(outPath), ".rpf") && !(dec[0] == 'R' && dec[1] == 'P' && dec[2] == 'F')) {
        throw std::runtime_error("Invalid RPF header for " + outPath);
    }
    if (!expectedChecksum.empty()) {
        std::string rawHex = sha256Hex(resp.body);
        std::string decHex = sha256Hex(dec);
        if (rawHex != expectedChecksum && decHex != expectedChecksum) {
            LOG("Checksum warning for " + outPath + ": hash may be computed differently",
                LogLevel::WARNING);
        } else {
            LOG("Checksum verified: " + outPath, LogLevel::INFO);
        }
    }
    if (!writeFileBytes(outPath, dec)) {
        throw std::runtime_error("Failed to write " + outPath);
    }
}
bool FiveMDumper::downloadQuiet(const std::string& url, const std::vector<uint8_t>& key,
                                const std::vector<uint8_t>& iv, const std::string& outPath) {
    auto resp = http_.get(url);
    if (resp.status == 404) return false;
    if (!resp.ok()) {
        LOG("Optional fetch failed (" + std::to_string(resp.status) + "): " + outPath,
            LogLevel::WARNING);
        return false;
    }
    for (int nonceLen = 12; nonceLen >= 8; nonceLen -= 4) {
        if ((int)iv.size() < nonceLen) continue;
        std::vector<uint8_t> nonce(iv.begin(), iv.begin() + nonceLen);
        try {
            auto dec = chacha20Xor(key, nonce, resp.body);
            if (dec.empty()) continue;
            if (writeFileBytes(outPath, dec)) return true;
        } catch (...) {}
    }
    return false;
}
static bool hasManifest(const std::string& dir) {
    std::error_code ec;
    if (!fs::exists(dir, ec)) return false;
    for (auto& e : fs::recursive_directory_iterator(dir, ec)) {
        if (!e.is_regular_file()) continue;
        std::string fn = e.path().filename().generic_string();
        if (fn == "fxmanifest.lua" || fn == "__resource.lua") return true;
    }
    return false;
}
static size_t countTree(const std::string& dir) {
    std::error_code ec;
    if (!fs::exists(dir, ec)) return 0;
    size_t n = 0;
    for (auto& e : fs::recursive_directory_iterator(dir, ec))
        if (e.is_regular_file()) ++n;
    return n;
}
bool FiveMDumper::unpackRpf(const std::string& rpfPath, const std::string& outDir) {
    std::string unpackerRel = resolveTool("Bin/Unpacker.exe");
    if (!fs::exists(unpackerRel)) {
        LOG("Unpacker.exe NOT FOUND (keresve: cwd + exe kornyezek) - " + outDir +
            " RPF-ei kitomorigatas nelkul maradnak!", LogLevel::WARNING);
        return false;
    }
    auto makeAbs = [](const std::string& p) {
        char buf[4096];
        DWORD n = GetFullPathNameA(p.c_str(), sizeof(buf), buf, nullptr);
        std::string full = (n && n < sizeof(buf)) ? buf : p;
        std::replace(full.begin(), full.end(), '/', '\\');
        return full;
    };
    std::string unpacker = makeAbs(unpackerRel);
    std::string rpf = makeAbs(rpfPath);
    std::string out = makeAbs(outDir);
    std::error_code ec;
    fs::create_directories(out, ec);
    size_t before = countTree(out);
    std::string cmd = "\"" + unpacker + "\" \"" + rpf + "\" \"" + out + "\"";
    std::wstring wcmd;
    int len = MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), -1, nullptr, 0);
    if (len <= 0) {
        LOG("Unpacker command conversion failed (err " + std::to_string(GetLastError()) + ")",
            LogLevel::WARNING);
        return false;
    }
    wcmd.resize(len - 1);
    MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), -1, wcmd.data(), len);
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, wcmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        LOG("Failed to launch Unpacker (err " + std::to_string(GetLastError()) + "): " + cmd,
            LogLevel::WARNING);
        return false;
    }
    DWORD wait = WaitForSingleObject(pi.hProcess, 120000);
    bool timedOut = (wait == WAIT_TIMEOUT);
    if (timedOut) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
    }
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (wait != WAIT_OBJECT_0) {
        LOG("Unpacker wait failed (result " + std::to_string(wait) + ") for " +
            fs::path(rpfPath).filename().generic_string() +
            " - a folyamat allapotat nem sikerult megallapitani.", LogLevel::WARNING);
        return false;
    }
    if (timedOut) {
        LOG("Unpacker TIMEOUT (120s) for " + fs::path(rpfPath).filename().generic_string() +
            " - a folyamat leallitva.", LogLevel::WARNING);
        return false;
    }
    size_t after = countTree(out);
    if (after <= before) {
        LOG("Unpacker produced NO new files for " + fs::path(rpfPath).filename().generic_string() +
            " (exit " + std::to_string(exitCode) + ") - nyers RPF megmentese...", LogLevel::WARNING);
        return false;
    }
    return true;
}
void FiveMDumper::fetchResource(const ResourceInfo& res) {
    std::string resName = safeName(res.name);
    if (std::find(checkpoint_.completed_resources.begin(), checkpoint_.completed_resources.end(),
                  resName) != checkpoint_.completed_resources.end()) {
        LOG("Resource '" + resName + "' already completed, skipping.", LogLevel::INFO);
        return;
    }
    std::string tempRes = tempDir + "/" + resName;
    std::string unpackedRes = unpackedDir + "/" + resName;
    auto hashPos = res.uri.find('#');
    if (hashPos == std::string::npos) {
        LOG("Resource has malformed uri: " + resName, LogLevel::ERROR);
        return;
    }
    std::vector<uint8_t> uriBytes = base64Decode(res.uri.substr(hashPos + 1));
    if (uriBytes.size() < 61) {
        LOG("Resource uri too short: " + resName, LogLevel::ERROR);
        return;
    }
    std::vector<uint8_t> iv(uriBytes.begin() + 53, uriBytes.begin() + 61);
    std::vector<uint8_t> xored(uriBytes.begin() + 19, uriBytes.end());
    std::vector<uint8_t> hmacKey(32);
    for (size_t i = 0; i < 32; ++i) hmacKey[i] = xored[i] ^ 0x69;
    std::string fileBase = res.fileServer.empty() ? (baseUrl_ + "/files") : res.fileServer;
    std::atomic<size_t> rejected{0};
    struct Task { std::string url, outPath, hash; std::vector<uint8_t> key; bool rpf; };
    std::vector<Task> tasks;
    tasks.reserve(res.files.size() + res.streamFiles.size());
    for (const auto& f : res.files) {
        if (!isSafeRelPath(f.name)) {
            LOG(resName + ": figyelmeztetes - unsafe file name megtagadva: '" + f.name + "'",
                LogLevel::WARNING);
            ++rejected;
            continue;
        }
        Task t;
        t.url = fileBase + "/" + res.name + "/" + urlQuote(f.name) + "?hash=" + f.hash;
        t.key = hmacSha256(hmacKey, f.name);
        t.outPath = (endsWith(toLower(f.name), ".rpf") ? tempRes : unpackedRes) + "/" + f.name;
        t.hash = f.hash;
        t.rpf = endsWith(toLower(f.name), ".rpf");
        tasks.push_back(std::move(t));
    }
    for (const auto& f : res.streamFiles) {
        if (!isSafeRelPath(f.name)) {
            LOG(resName + ": figyelmeztetes - unsafe stream file name megtagadva: '" + f.name + "'",
                LogLevel::WARNING);
            ++rejected;
            continue;
        }
        Task t;
        t.url = fileBase + "/" + res.name + "/" + urlQuote(f.name) + "?hash=" + f.hash;
        t.key = hmacSha256(hmacKey, f.name);
        t.outPath = unpackedRes + "/stream/" + f.name;
        t.hash = f.hash;
        t.rpf = false;
        tasks.push_back(std::move(t));
    }
    std::vector<std::string> rpfFiles;
    std::mutex rpfMtx;
    std::atomic<size_t> next{0};
    std::atomic<size_t> errors{0};
    ProgressBar bar("  " + resName, tasks.size());
    int workers = std::min(maxWorkers_, (int)tasks.size());
    std::vector<std::thread> pool;
    for (int w = 0; w < workers; ++w) {
        pool.emplace_back([&]() {
            for (;;) {
                size_t i = next.fetch_add(1);
                if (i >= tasks.size()) break;
                const Task& t = tasks[i];
                try {
                    downloadAndDecrypt(t.url, t.key, iv, t.outPath, t.hash,
                                       [&bar](size_t n) { bar.addBytes(n); },
                                       [&bar](size_t n) { bar.addExpected(n); });
                    if (t.rpf) {
                        std::lock_guard<std::mutex> lock(rpfMtx);
                        rpfFiles.push_back(t.outPath);
                    }
                } catch (const std::exception& e) {
                    LOG(std::string("Download error: ") + e.what(), LogLevel::WARNING);
                    ++errors;
                }
                bar.tick();
            }
        });
    }
    for (auto& th : pool) th.join();
    bar.finish();
    if (errors > 0) {
        LOG(resName + ": " + std::to_string(errors) + " file(s) failed", LogLevel::WARNING);
    }
    if (rejected > 0) {
        LOG(resName + ": " + std::to_string(rejected) +
            " file(s) megtagadva (biztonsagtalan fajlnev) - a resource NEM lett kesznek jelolve, "
            "a kovetkezo futas ujra letolli", LogLevel::ERROR);
    }
    if (!rpfFiles.empty()) {
        LOG("Unpacking " + std::to_string(rpfFiles.size()) + " RPF files for " + resName,
            LogLevel::INFO);
        std::vector<std::string> failedRpbs;
        for (auto& rpf : rpfFiles) {
            try {
                if (!unpackRpf(rpf, unpackedRes)) failedRpbs.push_back(rpf);
            } catch (...) { failedRpbs.push_back(rpf); }
        }
        if (!failedRpbs.empty()) {
            std::error_code ec;
            fs::create_directories(unpackedRes, ec);
            for (auto& rpf : failedRpbs) {
                std::string dest = unpackedRes + "/" + fs::path(rpf).filename().generic_string();
                fs::rename(rpf, dest, ec);
                if (ec) fs::copy_file(rpf, dest, fs::copy_options::overwrite_existing, ec);
            }
            LOG(resName + ": " + std::to_string(failedRpbs.size()) +
                " RPF kitomorigatase sikertelen - a nyers .rpf(ok) az Outputban!",
                LogLevel::WARNING);
        }
    }
    if (!hasManifest(unpackedRes)) {
        for (const char* cand : {"fxmanifest.lua", "__resource.lua"}) {
            if (!isSafeRelPath(cand)) {
                LOG(resName + ": figyelmeztetes - unsafe manifest name megtagadva: '" +
                    std::string(cand) + "'", LogLevel::WARNING);
                continue;
            }
            std::string url = fileBase + "/" + res.name + "/" + urlQuote(cand);
            std::vector<uint8_t> ckey = hmacSha256(hmacKey, cand);
            if (downloadQuiet(url, ckey, iv, unpackedRes + "/" + cand)) {
                LOG("Fetched " + std::string(cand) + " directly for " + resName, LogLevel::INFO);
                break;
            }
        }
        if (!hasManifest(unpackedRes)) {
            LOG(resName + ": fxmanifest NEM nyelheto el (benne van az RPF-ben, ami nem"
                " bomthat ki; probald masik kitomorigetovel)", LogLevel::WARNING);
        }
    }
    if (rejected > 0) return;
    checkpoint_.completed_resources.push_back(resName);
    checkpoint_.save();
}
bool FiveMDumper::run(const std::string& filterResource) {
    if (!getConfiguration()) return false;
    saveConfigCache();
    if (usingCachedConfig_) {
        std::cout << CLR(term::YELLOW) << "[!]" << CLR(term::RESET)
                  << " A konfiguracio cache-bol jol: a szerver most nem valaszol, vagy a token "
                     "lejart. Ha a letoltesek hibadnak, csatlakozz ujra a szerverhez a jatekban "
                     "es futtasd ujra a dumpert (a checkpoint folytatja).\n";
    }
    if (configFetched_ && !grants_.empty())
        writeTextFile(resourcesDir + "/Grants.txt", grants_);
    std::vector<ResourceInfo> sorted = resources_;
    std::sort(sorted.begin(), sorted.end(), [](const ResourceInfo& a, const ResourceInfo& b) {
        return toLower(a.name) < toLower(b.name);
    });
    std::vector<ResourceInfo> chosen;
    if (!filterResource.empty()) {
        for (auto& r : sorted)
            if (safeName(r.name) == safeName(filterResource)) chosen.push_back(r);
    } else {
        std::cout << "\n" << CLR(term::BOLD) << CLR(term::CYAN) << "Available Resources" << CLR(term::RESET) << "\n";
        std::cout << CLR(term::DIM) << std::string(60, '-') << CLR(term::RESET) << "\n";
        for (size_t i = 0; i < sorted.size(); ++i) {
            std::cout << CLR(term::CYAN) << "[" << std::setw(4) << (i + 1) << "]" << CLR(term::RESET)
                      << " " << sorted[i].name << "\n";
        }
        std::cout << CLR(term::DIM) << std::string(60, '-') << CLR(term::RESET) << "\n";
        std::cout << "Enter resources: indices (1,3), ranges (5-8), NAMES (pma-voice, ox_lib),\n";
        std::cout << "mixed ok; " << CLR(term::GREEN) << "'all'" << CLR(term::RESET)
                  << " or Enter = mind; " << CLR(term::YELLOW) << "'q'" << CLR(term::RESET) << " = kilép: ";
        std::map<std::string, const ResourceInfo*> byName;
        for (auto& r : sorted) byName[toLower(r.name)] = &r;
        std::string line;
        if (!std::getline(std::cin, line)) {
            std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET) << " Non-interactive, selecting all.\n";
            chosen = sorted;
        } else {
            line = trim(line);
            if (line.empty() || toLower(line) == "all") {
                chosen = sorted;
            } else if (toLower(line) == "q") {
                LOG("Cancelled by user.", LogLevel::INFO);
                return true;
            } else {
                for (auto& tok : split(line, ',')) {
                    tok = trim(tok);
                    if (tok.empty()) continue;
                    auto dash = tok.find('-');
                    if (dash != std::string::npos &&
                        tok.find_first_not_of("0123456789-") == std::string::npos) {
                        std::string a = trim(tok.substr(0, dash)), b = trim(tok.substr(dash + 1));
                        unsigned long long lo = 0, hi = 0;
                        if (!parseDigits(a, lo) || !parseDigits(b, hi)) {
                            std::cout << CLR(term::YELLOW) << "[!] Ignoring out-of-range: " << tok << CLR(term::RESET) << "\n";
                            continue;
                        }
                        if (lo > hi) std::swap(lo, hi);
                        if (lo < 1) lo = 1;
                        if (hi > sorted.size()) hi = sorted.size();
                        for (unsigned long long i = lo; i <= hi; ++i)
                            chosen.push_back(sorted[i - 1]);
                        continue;
                    }
                    if (tok.find_first_not_of("0123456789") == std::string::npos) {
                        unsigned long long idx = 0;
                        if (parseDigits(tok, idx) && idx >= 1 && idx <= sorted.size())
                            chosen.push_back(sorted[idx - 1]);
                        else std::cout << CLR(term::YELLOW) << "[!] Ignoring out-of-range: " << tok << CLR(term::RESET) << "\n";
                        continue;
                    }
                    auto it = byName.find(toLower(tok));
                    if (it != byName.end()) { chosen.push_back(*it->second); continue; }
                    std::vector<const ResourceInfo*> part;
                    for (auto& r : sorted)
                        if (toLower(r.name).find(toLower(tok)) != std::string::npos) part.push_back(&r);
                    if (part.size() == 1) chosen.push_back(*part[0]);
                    else if (part.size() > 1) {
                        std::cout << CLR(term::YELLOW) << "[?] '" << tok << "' tobbsze illeszkedik: ";
                        for (auto* p : part) std::cout << p->name << "  ";
                        std::cout << CLR(term::RESET) << "\n";
                    } else std::cout << CLR(term::YELLOW) << "[!] Nem leelheto resource: " << tok
                                     << CLR(term::RESET) << "\n";
                }
            }
        }
    }
    if (chosen.empty()) {
        LOG("No resources selected.", LogLevel::INFO);
        return false;
    }
    LOG("Processing " + std::to_string(chosen.size()) + " resource(s)...", LogLevel::INFO);
    for (const auto& r : chosen) fetchResource(r);
    bool allDone = !chosen.empty();
    for (const auto& r : chosen) {
        if (std::find(checkpoint_.completed_resources.begin(),
                      checkpoint_.completed_resources.end(),
                      safeName(r.name)) == checkpoint_.completed_resources.end()) {
            allDone = false;
        }
    }
    if (allDone) {
        checkpoint_.clear();
        LOG("All selected resources downloaded successfully.", LogLevel::SUCCESS);
    } else {
        LOG("Not every resource finished; the checkpoint is kept so the next run "
            "continues where this one stopped (reconnect in FiveM first if the "
            "token expired).", LogLevel::WARNING);
    }
    return true;
}
} 