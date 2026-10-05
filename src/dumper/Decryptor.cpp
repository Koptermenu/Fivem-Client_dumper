#include "Decryptor.h"
#include "../core/Logger.h"
#include "../crypto/ChaCha20.h"
#include "../crypto/ClientKey.h"
#include "../utils/Str.h"
#include "../utils/Term.h"
#include "../utils/Json.h"
#include "../utils/ProgressBar.h"
#include <windows.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>
namespace fs = std::filesystem;
namespace fivem {
static const std::vector<uint8_t> DEFAULT_KEY = {
    0xB3, 0xCB, 0x2E, 0x04, 0x87, 0x94, 0xD6, 0x73, 0x08, 0x23, 0xC4, 0x93, 0x7A, 0xBD, 0x18, 0xAD,
    0x6B, 0xE6, 0xDC, 0xB3, 0x91, 0x43, 0x0D, 0x28, 0xF9, 0x40, 0x9D, 0x48, 0x37, 0xB9, 0x38, 0xFB
};
static const uint8_t LUA_SIGNATURE[4] = {0x1B, 0x4C, 0x75, 0x61};
static const char* RSC7_HEADER = "RSC7";
static const char* RSC8_HEADER = "RSC8";
static const char* STREAM_EXTENSIONS[] = {
    ".awc", ".ybn", ".ydd", ".ydr", ".yft", ".ymap", ".ymf", ".ytd", ".ytyp"
};
namespace {
bool isFxap(const std::vector<uint8_t>& d) {
    return d.size() >= 4 && d[0] == 'F' && d[1] == 'X' && d[2] == 'A' && d[3] == 'P';
}
bool isLuaBytecode(const std::vector<uint8_t>& d) {
    return d.size() >= 4 && std::memcmp(d.data(), LUA_SIGNATURE, 4) == 0;
}
bool isRsc(const std::vector<uint8_t>& d) {
    return d.size() >= 4 &&
           (std::memcmp(d.data(), RSC7_HEADER, 4) == 0 ||
            std::memcmp(d.data(), RSC8_HEADER, 4) == 0);
}
bool isStreamFile(const std::string& lowerName) {
    for (const char* ext : STREAM_EXTENSIONS)
        if (endsWith(lowerName, ext)) return true;
    return false;
}
bool deriveInnerLayout(const std::vector<uint8_t>& d, size_t& ivOffset, size_t& payloadOffset) {
    if (d.size() >= 18) {
        const size_t metaLen = static_cast<size_t>(d[4]) | (static_cast<size_t>(d[5]) << 8);
        const size_t iv = 6 + metaLen;
        const size_t payload = iv + 12;
        if (payload < d.size()) {
            ivOffset = iv;
            payloadOffset = payload;
            return true;
        }
    }
    if (d.size() > 92) {
        ivOffset = 80;
        payloadOffset = 92;
        return true;
    }
    return false;
}
std::vector<uint8_t> decryptAt(const std::vector<uint8_t>& d, const std::vector<uint8_t>& key,
                              size_t payloadOffset, size_t ivOffset) {
    if (ivOffset + 12 > payloadOffset || payloadOffset >= d.size()) return {};
    std::vector<uint8_t> nonce(d.begin() + ivOffset, d.begin() + ivOffset + 12);
    std::vector<uint8_t> payload(d.begin() + payloadOffset, d.end());
    return chacha20Xor(key, nonce, payload);
}
bool probeAt(const std::vector<uint8_t>& d, const std::vector<uint8_t>& key,
             size_t payloadOffset, size_t ivOffset, bool (*valid)(const std::vector<uint8_t>&)) {
    if (ivOffset + 12 > payloadOffset || payloadOffset >= d.size()) return false;
    const size_t n = std::min<size_t>(32, d.size() - payloadOffset);
    std::vector<uint8_t> nonce(d.begin() + ivOffset, d.begin() + ivOffset + 12);
    std::vector<uint8_t> head(d.begin() + payloadOffset, d.begin() + payloadOffset + n);
    try {
        return valid(chacha20Xor(key, nonce, head));
    } catch (...) {
        return false;
    }
}
std::vector<uint8_t> findLuaBytecode(const std::vector<uint8_t>& d,
                                     const std::vector<std::vector<uint8_t>>& keys) {
    for (const auto& key : keys) {
        size_t iv = 0, payload = 0;
        if (deriveInnerLayout(d, iv, payload) && probeAt(d, key, payload, iv, isLuaBytecode))
            return decryptAt(d, key, payload, iv);
    }
    for (const auto& key : keys) {
        if (probeAt(d, key, 90, 78, isLuaBytecode)) return decryptAt(d, key, 90, 78);
    }
    for (const auto& key : keys) {
        for (size_t payload = 50; payload <= 150 && payload < d.size(); ++payload) {
            for (size_t iv = 38; iv <= 138 && iv + 12 <= payload; ++iv) {
                if (probeAt(d, key, payload, iv, isLuaBytecode))
                    return decryptAt(d, key, payload, iv);
            }
        }
    }
    return {};
}
size_t findFilenameEnd(const std::vector<uint8_t>& d) {
    for (size_t i = 0; i < d.size(); ++i) {
        for (const char* ext : STREAM_EXTENSIONS) {
            const size_t len = std::strlen(ext);
            if (i + len <= d.size() && std::memcmp(d.data() + i, ext, len) == 0) return i + len;
        }
    }
    return std::string::npos;
}
std::vector<uint8_t> decryptStreamBuffer(const std::vector<uint8_t>& d,
                                        const std::vector<uint8_t>& key) {
    if (d.size() < 100) return {};
    const size_t nameEnd = findFilenameEnd(d);
    if (nameEnd != std::string::npos) {
        for (size_t extra : {size_t(0), size_t(1), size_t(2), size_t(4), size_t(8)}) {
            const size_t iv = nameEnd + extra;
            if (probeAt(d, key, iv + 12, iv, isRsc)) return decryptAt(d, key, iv + 12, iv);
        }
    }
    for (size_t iv = 40; iv <= 120; ++iv) {
        if (probeAt(d, key, iv + 12, iv, isRsc)) return decryptAt(d, key, iv + 12, iv);
    }
    return {};
}
std::vector<uint8_t> findStreamPayload(const std::vector<uint8_t>& d,
                                       const std::vector<std::vector<uint8_t>>& keys) {
    for (const auto& key : keys) {
        size_t iv = 0, payload = 0;
        if (deriveInnerLayout(d, iv, payload) && probeAt(d, key, payload, iv, isRsc))
            return decryptAt(d, key, payload, iv);
        std::vector<uint8_t> scanned = decryptStreamBuffer(d, key);
        if (!scanned.empty()) return scanned;
    }
    return {};
}
std::vector<uint8_t> decryptAny(const std::vector<uint8_t>& d,
                                const std::vector<std::vector<uint8_t>>& keys) {
    for (const auto& key : keys) {
        size_t iv = 0, payload = 0;
        if (!deriveInnerLayout(d, iv, payload)) continue;
        std::vector<uint8_t> out = decryptAt(d, key, payload, iv);
        if (!out.empty()) return out;
    }
    return {};
}
std::wstring widen(const std::string& s) {
    if (s.empty()) return L"";
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), w.data(), n);
    return w;
}
std::wstring quoteArg(const std::string& a) {
    std::wstring w = widen(a);
    if (w.find_first_of(L" \t\"") == std::wstring::npos) return w;
    std::wstring out = L"\"";
    for (wchar_t c : w) {
        if (c == L'\\') out += L"\\\\";
        else if (c == L'"') out += L"\\\"";
        else out += c;
    }
    out += L'"';
    return out;
}
struct ProcResult {
    bool started = false;
    DWORD exitCode = 1;
    std::string out;
    std::string errOut;
    bool overflow = false;
};
ProcResult runTool(const std::string& executable, const std::vector<std::string>& args) {
    ProcResult r;
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE outRd = nullptr, outWr = nullptr, errRd = nullptr, errWr = nullptr, nul = nullptr;
    if (!CreatePipe(&outRd, &outWr, &sa, 0) || !CreatePipe(&errRd, &errWr, &sa, 0)) {
        if (outRd) CloseHandle(outRd);
        if (outWr) CloseHandle(outWr);
        return r;
    }
    SetHandleInformation(outRd, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(errRd, HANDLE_FLAG_INHERIT, 0);
    nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (nul == INVALID_HANDLE_VALUE) {
        CloseHandle(outRd); CloseHandle(outWr);
        CloseHandle(errRd); CloseHandle(errWr);
        return r;
    }
    std::wstring cmd = quoteArg(executable);
    for (const auto& a : args) cmd += L" " + quoteArg(a);
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(L'\0');
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nul;
    si.hStdOutput = outWr;
    si.hStdError = errWr;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
        CloseHandle(outRd); CloseHandle(outWr);
        CloseHandle(errRd); CloseHandle(errWr);
        CloseHandle(nul);
        return r;
    }
    r.started = true;
    CloseHandle(outWr);
    CloseHandle(errWr);
    CloseHandle(nul);
    const size_t kMaxOutput = 128u * 1024u * 1024u;
    HANDLE pipes[2] = {outRd, errRd};
    std::string* sinks[2] = {&r.out, &r.errOut};
    std::thread drainers[2];
    for (int i = 0; i < 2; ++i) {
        drainers[i] = std::thread([&, i]() {
            char buf[8192];
            DWORD n = 0;
            while (ReadFile(pipes[i], buf, sizeof(buf), &n, nullptr) && n > 0) {
                if (sinks[i]->size() >= kMaxOutput) { r.overflow = true; continue; }
                sinks[i]->append(buf, n);
            }
            CloseHandle(pipes[i]);
        });
    }
    for (auto& t : drainers) t.join();
    WaitForSingleObject(pi.hProcess, 300000);
    GetExitCodeProcess(pi.hProcess, &r.exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return r;
}
std::string resolveJava() {
    if (const char* home = getenv("JAVA_HOME")) {
        std::string candidate = std::string(home) + "\\bin\\java.exe";
        if (fs::exists(candidate)) return candidate;
    }
    return "java.exe";
}
bool fixUnknownLabels(const std::string& asmPath) {
    std::ifstream in(asmPath, std::ios::binary);
    if (!in.is_open()) return false;
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    struct Label { long long number; size_t line; };
    std::vector<Label> labels;
    std::vector<std::string> lines;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t eol = text.find('\n', pos);
        if (eol == std::string::npos) eol = text.size();
        lines.push_back(text.substr(pos, eol - pos));
        pos = eol + 1;
    }
    auto parseLabel = [](const std::string& line, long long& number) -> bool {
        size_t i = line.find(".label");
        if (i == std::string::npos) return false;
        i += 7;
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
        if (i >= line.size() || line[i] != 'l') return false;
        ++i;
        if (i >= line.size() || !std::isdigit(static_cast<unsigned char>(line[i]))) return false;
        number = 0;
        while (i < line.size() && std::isdigit(static_cast<unsigned char>(line[i])))
            number = number * 10 + (line[i++] - '0');
        return true;
    };
    for (size_t i = 0; i < lines.size(); ++i) {
        long long n = 0;
        if (parseLabel(lines[i], n)) labels.push_back({n, i});
    }
    if (labels.empty()) return false;
    auto known = [&](long long n) {
        for (const auto& l : labels) if (l.number == n) return true;
        return false;
    };
    bool changed = false;
    for (size_t i = 0; i < lines.size(); ++i) {
        std::string t = trim(lines[i]);
        if (!startsWith(t, "jmp")) continue;
        std::string rest = trim(t.substr(3));
        if (rest.empty()) continue;
        if (rest[0] == 'l') rest = rest.substr(1);
        if (rest.find_first_not_of("0123456789") != std::string::npos) continue;
        long long target = 0;
        for (char c : rest) target = target * 10 + (c - '0');
        if (known(target)) continue;
        long long replacement = 0;
        bool found = false;
        for (const auto& l : labels) if (l.number == target) { replacement = l.number; found = true; break; }
        if (!found) {
            for (const auto& l : labels) if (l.line > i) { replacement = l.number; found = true; break; }
        }
        if (!found) {
            long long best = 0;
            long long bestDelta = -1;
            for (const auto& l : labels) {
                const long long delta = l.number > target ? l.number - target : target - l.number;
                if (!found || delta < bestDelta) { bestDelta = delta; best = l.number; found = true; }
            }
            replacement = best;
        }
        if (!found) continue;
        const std::string replacementLine = "jmp          " + std::to_string(replacement);
        if (!lines[i].empty() && lines[i].back() == '\r') lines[i].pop_back();
        const size_t indent = lines[i].find_first_not_of(" \t");
        lines[i] = std::string(indent == std::string::npos ? 0 : indent, ' ') + replacementLine;
        changed = true;
    }
    if (!changed) return false;
    std::ofstream out(asmPath, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) return false;
    for (size_t i = 0; i < lines.size(); ++i) out << lines[i] << "\n";
    return out.good();
}
std::string replaceExtension(const std::string& path, const std::string& newExt) {
    const size_t slash = path.find_last_of("/\\");
    const size_t dot = path.find_last_of('.');
    if (dot == std::string::npos || (slash != std::string::npos && dot < slash)) return path + newExt;
    return path.substr(0, dot) + newExt;
}
}
Decryptor::Decryptor(std::string serverDir)
    : serverDir_(std::move(serverDir)) {
    outputDir = "Servers/" + serverDir_ + "/Output";
    tempDir = "Servers/" + serverDir_ + "/TempCompiled";
    unpackedDir = "Servers/" + serverDir_ + "/Unpacked";
}
bool Decryptor::loadGrants() {
    std::string path = "Servers/" + serverDir_ + "/Resources/Grants.txt";
    auto data = readFileBytes(path);
    if (!data) {
        LOG("Nincs kulcstoken: " + path, LogLevel::ERROR);
        LOG("A .fxap fajlokat a szerver kulcsaival oldjuk fel, es a tokenbol jonnek. "
            "Futtasd meg a letoltest (1. fazis) a FiveM-hez csatlakozva, vagy másold vissza "
            "a Grants.txt-t a helyere. Addig egyetlen .fxap sem dekódolható.",
            LogLevel::ERROR);
        return false;
    }
    grantsLoaded_ = true;    std::string token(data->begin(), data->end());
    auto parts = splitStr(token, ".");
    if (parts.size() < 2) {
        LOG("Malakultszeru kulcstoken: " + path + " (nincs benne pont)", LogLevel::ERROR);
        return false;
    }
    std::string payload = parts[1];
    size_t mod = payload.size() % 4;
    if (mod) payload.append(4 - mod, '=');
    std::vector<uint8_t> raw = base64Decode(payload);
    try {
        Json js = Json::parse(std::string(raw.begin(), raw.end()));
        for (auto& kv : js.at("grants").items()) grantsMap_[kv.first] = {kv.second.asString(), ""};
        for (auto& kv : js.at("grants_clk").items()) grantsMap_[kv.first].second = kv.second.asString();
    } catch (const std::exception& e) {
        LOG(std::string("Grants parse error: ") + e.what(), LogLevel::ERROR);
        return false;
    }
    LOG("Grants loaded: " + std::to_string(grantsMap_.size()) + " resource key(s)", LogLevel::INFO);
    return true;
}
bool Decryptor::verifyEncrypted(const std::string& path) const {
    auto buf = readFileBytes(path);
    return buf && isFxap(*buf);
}
std::vector<uint8_t> Decryptor::decryptFile(const std::string& path,
                                            const std::vector<uint8_t>& key) const {
    auto buf = readFileBytes(path);
    if (!buf || buf->size() < 86 || !isFxap(*buf)) return {};
    return decryptAt(*buf, key, 86, 74);
}
Decryptor::ResourceKeys Decryptor::resolveKeys(uint32_t resourceId,
                                               const std::string& resourceName) {
    ResourceKeys keys;
    const std::string idStr = std::to_string(resourceId);
    auto it = grantsMap_.find(idStr);
    if (it == grantsMap_.end()) {
        LOG(resourceName + ": nincs grant a resource ID-hoz (" + idStr + ")", LogLevel::WARNING);
        return keys;
    }
    if (!it->second.first.empty()) {
        std::vector<uint8_t> server = hexDecode(it->second.first);
        if (server.size() == 32) {
            keys.serverKeyHex = toLower(it->second.first);
            keys.serverKeyValid = true;
            keys.candidates.push_back(std::move(server));
        } else {
            LOG(resourceName + ": hibas grant (" + std::to_string(server.size()) +
                " bajt, 32 kell)", LogLevel::WARNING);
        }
    }
    if (!it->second.second.empty()) {
        std::vector<uint8_t> clk = hexDecode(it->second.second);
        std::string err;
        std::vector<uint8_t> client = deriveClientKey(resourceId, clk, err);
        if (client.size() == 32) {
            keys.clientKeyHex = hexEncode(client);
            keys.clientKeyValid = true;
            keys.candidates.push_back(std::move(client));
        } else {
            keys.clientKeyError = err;
        }
    }
    std::vector<std::vector<uint8_t>> unique;
    for (auto& c : keys.candidates) {
        bool seen = false;
        for (auto& u : unique) if (u == c) { seen = true; break; }
        if (!seen) unique.push_back(std::move(c));
    }
    keys.candidates = std::move(unique);
    return keys;
}
void Decryptor::processLuaFile(const std::vector<uint8_t>& buf, const std::string& outPath,
                               const std::string& resourceName, const std::string& relFile) {
    const std::string jar = resolveTool("Tools/Decompile/unluac54.jar");
    const std::string java = resolveJava();
    const std::string tempRoot = tempDir + "/" + resourceName + "/";
    const std::string luacPath = tempRoot + relFile + "c";
    const std::string asmPath = tempRoot + relFile + ".asm";
    const std::string fixedPath = tempRoot + relFile + ".fixed.luac";
    auto saveFallback = [&](const std::string& reason, bool keepAssembly) {
        const std::string bytecodeOut = endsWith(toLower(outPath), ".lua")
                                            ? outPath + "c"
                                            : outPath + ".luac";
        const std::string assemblyOut = endsWith(toLower(outPath), ".lua")
                                            ? replaceExtension(outPath, ".asm")
                                            : outPath + ".asm";
        std::error_code ec;
        fs::create_directories(fs::path(bytecodeOut).parent_path(), ec);
        fs::remove(outPath, ec);
        if (!writeFileBytes(bytecodeOut, buf))
            LOG("Nem irhato a bytecode masolat: " + bytecodeOut, LogLevel::WARNING);
        if (keepAssembly) {
            auto listing = readFileBytes(asmPath);
            if (listing && !writeFileBytes(assemblyOut, *listing))
                LOG("Nem irhato az assembly masolat: " + assemblyOut, LogLevel::WARNING);
        }
        LOG("Lua decompilation FAILED for " + relFile + " (" + reason +
            ") - a bytecode megmaradt: " + bytecodeOut, LogLevel::WARNING);
        ++failed_;
    };
    fs::path outp(outPath);
    if (outp.has_parent_path()) fs::create_directories(outp.parent_path());
    if (!writeFileBytes(luacPath, buf)) {
        LOG("Nem irhato a bytecode: " + luacPath, LogLevel::WARNING);
        ++failed_;
        return;
    }
    if (!fs::exists(jar)) {
        saveFallback("unluac54.jar hiányzik", false);
        return;
    }
    ProcResult direct = runTool(java, {"-jar", jar, luacPath});
    if (direct.overflow) {
        saveFallback("az unluac kimenete meghaladta a 128 MB limitet", false);
        return;
    }
    if (direct.started && direct.exitCode == 0 && direct.out.size() >= 10) {
        writeTextFile(outPath, direct.out);
        LOG("Lua decompiled: " + relFile, LogLevel::INFO);
        ++decryptedOk_;
        return;
    }
    std::error_code ec;
    fs::remove(asmPath, ec);
    ProcResult dis = runTool(java, {"-jar", jar, "--disassemble", luacPath, "-o", asmPath});
    if (!dis.started || dis.exitCode != 0 || !fs::exists(asmPath)) {
        saveFallback("az unluac nem tudta decompile-olni vagy disassemble-olni", false);
        return;
    }
    for (int attempt = 0; attempt < 10; ++attempt) {
        fs::remove(fixedPath, ec);
        ProcResult assembled = runTool(java, {"-jar", jar, "--assemble", asmPath, "-o", fixedPath});
        if (assembled.started && assembled.exitCode == 0 && fs::exists(fixedPath)) {
            ProcResult repaired = runTool(java, {"-jar", jar, fixedPath});
            if (repaired.exitCode == 0 && repaired.out.size() >= 10) {
                writeTextFile(outPath, repaired.out);
                LOG("Lua decompiled after bytecode repair: " + relFile, LogLevel::INFO);
                ++decryptedOk_;
                return;
            }
        }
        if (!fixUnknownLabels(asmPath)) break;
    }
    saveFallback("az unluac decompilalasa meghiusult", true);
}
void Decryptor::decryptResourceFile(const std::string& resourcePath, const std::string& relFile,
                                    const ResourceKeys& keys, const std::string& resourceName) {
    const std::string fullPath = resourcePath + "/" + relFile;
    const std::string outputPath = outputDir + "/" + resourceName + "/" + relFile;
    if (!fs::exists(fullPath)) return;
    if (!verifyEncrypted(fullPath)) {
        std::error_code ec;
        fs::create_directories(fs::path(outputPath).parent_path(), ec);
        fs::copy_file(fullPath, outputPath, fs::copy_options::overwrite_existing, ec);
        if (!ec) ++copied_; else ++failed_;
        return;
    }
    auto stage1 = decryptFile(fullPath, DEFAULT_KEY);
    if (stage1.empty()) {
        LOG("Initial decryption failed: " + relFile, LogLevel::WARNING);
        ++failed_;
        return;
    }
    auto keepRaw = [&]() {
        const std::string rawPath = outputPath + ".raw";
        std::error_code ec;
        fs::create_directories(fs::path(rawPath).parent_path(), ec);
        auto raw = readFileBytes(fullPath);
        if (raw && writeFileBytes(rawPath, *raw))
            LOG("Nyers titkosított masolat kiirva: " + rawPath, LogLevel::WARNING);
        else
            LOG("Nyers titkosított masolat nem irhato: " + rawPath, LogLevel::WARNING);
    };
    const std::string lower = toLower(relFile);
    try {
        std::vector<uint8_t> plain;
        if (endsWith(lower, ".lua")) {
            plain = findLuaBytecode(stage1, keys.candidates);
            if (plain.empty()) {
                const std::string hint = keys.candidates.size() < 2
                    ? " (csak a szerver kulcs volt elerheto)"
                    : "";
                LOG("No valid Lua header for " + relFile + " - egyik " +
                    std::to_string(keys.candidates.size()) + " kulcs sem ad vissza Lua bytecot" +
                    hint, LogLevel::WARNING);
                ++failed_;
                keepRaw();
                return;
            }
            processLuaFile(plain, outputPath, resourceName, relFile);
            return;
        }
        if (isStreamFile(lower)) {
            plain = findStreamPayload(stage1, keys.candidates);
            if (plain.empty()) {
                LOG("No valid RSC stream for " + relFile, LogLevel::WARNING);
                ++failed_;
                keepRaw();
                return;
            }
        } else {
            plain = decryptAny(stage1, keys.candidates);
            if (plain.empty()) {
                LOG("Buffer decryption failed: " + relFile, LogLevel::WARNING);
                ++failed_;
                keepRaw();
                return;
            }
        }
        if (!writeFileBytes(outputPath, plain)) {
            LOG("Nem irhato: " + outputPath, LogLevel::WARNING);
            ++failed_;
            return;
        }
        ++decryptedOk_;
    } catch (const std::exception& e) {
        LOG("Decrypt error " + relFile + ": " + e.what(), LogLevel::WARNING);
        ++failed_;
    }
}
void Decryptor::decryptResource(const std::string& resourcePath, const std::string& resourceName) {
    LOG("Processing resource: " + resourceName, LogLevel::INFO);
    const std::string fxapPath = resourcePath + "/.fxap";
    std::error_code itErr;
    std::vector<fs::path> files;
    if (fs::exists(fxapPath)) {
        for (auto& e : fs::recursive_directory_iterator(resourcePath, itErr))
            if (e.is_regular_file() && e.path().filename() != ".fxap") files.push_back(e.path());
    } else {
        for (auto& e : fs::recursive_directory_iterator(resourcePath, itErr))
            if (e.is_regular_file()) files.push_back(e.path());
    }
    if (itErr) {
        LOG(resourceName + ": figyelmeztetes - a konyvtarbejaras hiba miatt megszakadt: " +
            itErr.message() + " - a fajlalista reszleges", LogLevel::WARNING);
        ++failed_;
    }
    ResourceKeys keys;
    if (fs::exists(fxapPath)) {
        auto fxapBuf = decryptFile(fxapPath, DEFAULT_KEY);
        if (fxapBuf.size() < 78) {
            LOG("Unable to decrypt .fxap for " + resourceName +
                " - a resource titkositatlanul atmasolva", LogLevel::WARNING);
            ++failed_;
        } else {
            const uint32_t resourceId = be32(fxapBuf.data() + 74);
            LOG("Resource ID: " + std::to_string(resourceId), LogLevel::INFO);
            keys = resolveKeys(resourceId, resourceName);
            if (keys.serverKeyValid) LOG(resourceName + ": grants kulcs " + keys.serverKeyHex, LogLevel::INFO);
            if (keys.clientKeyValid) LOG(resourceName + ": klien(s kulcs " + keys.clientKeyHex, LogLevel::INFO);
            if (!keys.clientKeyError.empty())
                LOG(resourceName + ": klien(s kulcs nem elerheto - " + keys.clientKeyError, LogLevel::WARNING);
            if (keys.candidates.empty()) {
                LOG(resourceName + ": nincs hasznalhato kulcs, a resource atmasolva", LogLevel::WARNING);
                ++failed_;
            }
        }
    }
    const bool copyOnly = !fs::exists(fxapPath) || keys.candidates.empty();
    ProgressBar bar("  " + resourceName, files.size());
    std::atomic<size_t> next{0};
    const int workers = 6;
    std::vector<std::thread> pool;
    for (int w = 0; w < workers; ++w) {
        pool.emplace_back([&]() {
            for (;;) {
                const size_t i = next.fetch_add(1);
                if (i >= files.size()) break;
                std::string rel;
                try {
                    rel = fs::relative(files[i], resourcePath).generic_string();
                    if (copyOnly) {
                        const std::string out = outputDir + "/" + resourceName + "/" + rel;
                        std::error_code ec;
                        fs::create_directories(fs::path(out).parent_path(), ec);
                        fs::copy_file(files[i], out, fs::copy_options::overwrite_existing, ec);
                        if (!ec) ++copied_; else ++failed_;
                    } else {
                        decryptResourceFile(resourcePath, rel, keys, resourceName);
                    }
                } catch (const std::exception& e) {
                    LOG("File error (" + rel + "): " + std::string(e.what()), LogLevel::WARNING);
                    ++failed_;
                } catch (...) {
                    LOG("File error (" + rel + "): ismeretlen hiba a " + resourceName +
                        " eroforr feldolgozasa kozben", LogLevel::WARNING);
                    ++failed_;
                }
                bar.tick();
            }
        });
    }
    for (auto& t : pool) t.join();
    bar.finish();
}
bool Decryptor::runAll() {
    decryptedOk_ = failed_ = copied_ = 0;
    if (!fs::exists(unpackedDir)) {
        LOG("No Unpacked/ directory found - run the dumper first.", LogLevel::ERROR);
        ++failed_;
        return false;
    }
    std::vector<std::string> dirs;
    std::error_code itErr;
    for (auto& e : fs::directory_iterator(unpackedDir, itErr))
        if (e.is_directory()) dirs.push_back(e.path().generic_string());
    if (itErr) {
        LOG("figyelmeztetes - a " + unpackedDir +
            " konyvtarbejarasa hiba miatt megszakadt: " + itErr.message() +
            " - az eroforrlista reszleges", LogLevel::WARNING);
        ++failed_;
    }
    std::sort(dirs.begin(), dirs.end());
    if (dirs.empty()) {
        LOG("Nothing to process.", LogLevel::INFO);
        return failed_ == 0;
    }
    bool anyEncrypted = false;
    for (auto& d : dirs) {
        std::error_code ec;
        if (fs::exists(fs::path(d) / ".fxap", ec)) { anyEncrypted = true; break; }
    }
    if (!anyEncrypted) {
        std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET)
                  << " Nincs titkositott ereforras - a dekodolasi fazis kihagyva.\n";
        LOG("No encrypted resources - skipping decryption phase", LogLevel::INFO);
        size_t moved = 0, fileCount = 0;
        for (auto& d : dirs) {
            std::string name = fs::path(d).filename().generic_string();
            fs::path dest = fs::path(outputDir) / name;
            std::error_code ec;
            if (!fs::exists(dest, ec)) {
                fs::create_directories(dest.parent_path(), ec);
                fs::rename(d, dest, ec);
            }
            if (ec) {
                fs::create_directories(dest, ec);
                fs::copy(d, dest,
                         fs::copy_options::recursive | fs::copy_options::overwrite_existing, ec);
                if (!ec) fs::remove_all(d, ec);
            }
            if (!ec) {
                ++moved;
                std::error_code walkErr;
                for (auto& f : fs::recursive_directory_iterator(dest, walkErr))
                    if (f.is_regular_file()) ++fileCount;
                if (walkErr) {
                    LOG("figyelmeztetes - " + name + ": a fajlszamlalas megszakadt: " +
                        walkErr.message() + " - a bejelentett fajlszam csak reszleges", LogLevel::WARNING);
                    ++failed_;
                }
            } else {
                LOG("Move failed for " + name + ": " + ec.message(), LogLevel::ERROR);
                ++failed_;
            }
        }
        copied_ = (int)fileCount;
        LOG("Moved " + std::to_string(moved) + " resource(s) (" + std::to_string(fileCount) +
            " files) directly to Output - no decryption needed", LogLevel::SUCCESS);
        return failed_ == 0;
    }
    if (!loadGrants()) { ++failed_; return false; }
    LOG("Found " + std::to_string(dirs.size()) + " resource(s) to process", LogLevel::INFO);
    for (auto& d : dirs) {
        decryptResource(d, fs::path(d).filename().string());
    }
    LOG("Decryption stats - ok:" + std::to_string(decryptedOk_.load()) +
        " copied:" + std::to_string(copied_.load()) + " failed:" + std::to_string(failed_.load()),
        LogLevel::SUCCESS);
    return failed_ == 0;
}
} 