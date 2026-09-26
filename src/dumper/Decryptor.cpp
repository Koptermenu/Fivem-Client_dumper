#include "Decryptor.h"

#include "../core/Logger.h"
#include "../crypto/Sha256.h"
#include "../crypto/ChaCha20.h"
#include "../crypto/AesCbc.h"
#include "../utils/Str.h"
#include "../utils/Term.h"
#include "../utils/Json.h"
#include "../utils/ProgressBar.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>
#include <cstdio>

namespace fs = std::filesystem;

namespace fivem {

// Hardcoded keys (same as python)
static const std::vector<uint8_t> DEFAULT_KEY = {
    0xB3, 0xCB, 0x2E, 0x04, 0x87, 0x94, 0xD6, 0x73, 0x08, 0x23, 0xC4, 0x93, 0x7A, 0xBD, 0x18, 0xAD,
    0x6B, 0xE6, 0xDC, 0xB3, 0x91, 0x43, 0x0D, 0x28, 0xF9, 0x40, 0x9D, 0x48, 0x37, 0xB9, 0x38, 0xFB
};
static const std::vector<uint8_t> AES_KEY = {
    0x7A, 0xBA, 0x8D, 0x53, 0x25, 0x5B, 0x0E, 0xFD, 0x16, 0xBD, 0x35, 0x22, 0xA0, 0xB9, 0x26, 0xA5,
    0x61, 0x83, 0x2E, 0xEC, 0xA2, 0x4B, 0xFD, 0x56, 0x9E, 0xC0, 0x1D, 0x8F, 0x38, 0x40, 0x54, 0x6D
};
static const std::string LUA_HEADER_HEX = "1b4c7561540019930d0a1a0a0408087856";

Decryptor::Decryptor(std::string serverDir)
    : serverDir_(std::move(serverDir)) {
    outputDir = "Servers/" + serverDir_ + "/Output";
    tempDir = "Servers/" + serverDir_ + "/TempCompiled";
    unpackedDir = "Servers/" + serverDir_ + "/Unpacked";
}

bool Decryptor::loadGrants() {
    std::string path = "Servers/" + serverDir_ + "/Resources/Grants.txt";
    auto data = readFileBytes(path);
    if (!data) { LOG("No Grants.txt found", LogLevel::ERROR); return false; }
    std::string token(data->begin(), data->end());
    auto parts = splitStr(token, ".");
    if (parts.size() < 2) { LOG("Malformed grants token", LogLevel::ERROR); return false; }
    std::string payload = parts[1];
    // pad
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
    return true;
}

bool Decryptor::verifyEncrypted(const std::string& path) const {
    auto buf = readFileBytes(path);
    if (!buf || buf->size() < 4) return false;
    return (*buf)[0] == 'F' && (*buf)[1] == 'X' && (*buf)[2] == 'A' && (*buf)[3] == 'P';
}

std::vector<uint8_t> Decryptor::decryptFile(const std::string& path,
                                            const std::vector<uint8_t>& key) const {
    auto buf = readFileBytes(path);
    if (!buf || buf->size() < 86) return {};
    if (!((*buf)[0] == 'F' && (*buf)[1] == 'X' && (*buf)[2] == 'A' && (*buf)[3] == 'P')) return {};
    std::vector<uint8_t> iv(buf->begin() + 74, buf->begin() + 86);
    std::vector<uint8_t> enc(buf->begin() + 86, buf->end());
    return chacha20Xor(key, iv, enc);
}

std::vector<uint8_t> Decryptor::decryptBuffer(const std::vector<uint8_t>& data,
                                              const std::vector<uint8_t>& key) const {
    if (data.size() < 92) return {};
    std::vector<uint8_t> iv(data.begin() + 80, data.begin() + 92);
    std::vector<uint8_t> enc(data.begin() + 92, data.end());
    return chacha20Xor(key, iv, enc);
}

namespace {

// Canonical form used for both sides of the comparison: lowercase, '/' separators,
// no './' prefix and no empty segments.
std::string normalizeRelPath(const std::string& path) {
    std::string low = toLower(path);
    std::replace(low.begin(), low.end(), '\\', '/');
    std::vector<std::string> parts;
    for (const std::string& seg : split(low, '/'))
        if (!seg.empty() && seg != ".") parts.push_back(seg);
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) out += '/';
        out += parts[i];
    }
    return out;
}

bool isNameStart(char c) {
    return c == '_' || std::isalpha(static_cast<unsigned char>(c)) != 0;
}

bool isNameChar(char c) {
    return c == '_' || std::isalnum(static_cast<unsigned char>(c)) != 0;
}

// End offset of the Lua long bracket (string or comment) opening at pos, 0 if none.
size_t longBracketEnd(const std::string& text, size_t pos) {
    if (pos >= text.size() || text[pos] != '[') return 0;
    size_t q = pos + 1;
    while (q < text.size() && text[q] == '=') ++q;
    if (q >= text.size() || text[q] != '[') return 0;
    std::string close = "]" + std::string(q - pos - 1, '=') + "]";
    size_t e = text.find(close, q + 1);
    return e == std::string::npos ? text.size() : e + close.size();
}

// Match the 17-byte Lua 5.4 header prefix: signature, version, format, LUAC_DATA, the
// three sizeof size bytes (04 08 08 on stock x64 Windows) and the low byte of LUAC_INT (0x5678).
bool hasLuaHeader(const std::vector<uint8_t>& data) {
    const size_t headerLen = (LUA_HEADER_HEX.size() + 1) / 2;
    if (data.size() < headerLen) return false;
    std::string hex = hexEncode(std::vector<uint8_t>(data.begin(), data.begin() + headerLen));
    return hex.rfind(LUA_HEADER_HEX, 0) == 0;
}

// One path segment against one pattern segment: '?' is one character, '*' any run.
bool segmentMatch(const std::string& pattern, const std::string& text) {
    size_t p = 0, t = 0, star = std::string::npos, backtrack = 0;
    while (t < text.size()) {
        if (p < pattern.size() && (pattern[p] == '?' || pattern[p] == text[t])) { ++p; ++t; }
        else if (p < pattern.size() && pattern[p] == '*') { star = p++; backtrack = t; }
        else if (star != std::string::npos) { p = star + 1; t = ++backtrack; }
        else return false;
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}

bool globMatchSegments(const std::vector<std::string>& pattern, size_t pi,
                       const std::vector<std::string>& text, size_t ti) {
    if (pi == pattern.size()) return ti == text.size();
    if (pattern[pi] == "**") {
        for (size_t k = ti; k <= text.size(); ++k)
            if (globMatchSegments(pattern, pi + 1, text, k)) return true;
        return false;
    }
    if (ti == text.size()) return false;
    if (!segmentMatch(pattern[pi], text[ti])) return false;
    return globMatchSegments(pattern, pi + 1, text, ti + 1);
}

bool globMatch(const std::string& pattern, const std::string& path) {
    return globMatchSegments(split(pattern, '/'), 0, split(path, '/'), 0);
}

// Literal membership first, then the stored globs. A pattern-free entry therefore
// still matches only itself, which keeps this a strict superset of set lookup.
bool matchesManifestSet(const std::set<std::string>& files, const std::string& rel) {
    if (files.count(rel)) return true;
    for (const std::string& entry : files) {
        if (entry.find('*') == std::string::npos && entry.find('?') == std::string::npos) continue;
        if (globMatch(entry, rel)) return true;
    }
    return false;
}

} // namespace

// Parses the resource manifest once and collects the paths each side receives.
// Recognised: client_script(s), server_script(s), shared_script(s), the files /
// file block and the top-level server_only flag. Script directives may use globs,
// which detectLuaType matches too. files entries default to the client, because a
// resource ships its assets to the client; a shared entry is stored in both sets,
// while an explicit server_script entry is also recorded in serverScriptFiles so
// that it outranks a files membership. Anything unlisted stays unclassified.
Decryptor::LuaManifest Decryptor::parseLuaManifest(const std::string& resourcePath) {
    enum Side { SideNone, SideClient, SideServer, SideBoth };
    LuaManifest manifest;

    auto data = readFileBytes(resourcePath + "/fxmanifest.lua");
    if (!data) data = readFileBytes(resourcePath + "/__resource.lua");
    if (!data) return manifest;

    const std::string text(data->begin(), data->end());
    const size_t n = text.size();
    size_t i = 0;

    auto add = [&](const std::string& raw, Side side) {
        std::string p = normalizeRelPath(raw);
        if (p.empty()) return;
        if (side == SideClient || side == SideBoth) manifest.clientFiles.insert(p);
        if (side == SideServer || side == SideBoth) manifest.serverFiles.insert(p);
        if (side == SideServer) manifest.serverScriptFiles.insert(p);
    };
    auto readQuoted = [&]() {
        char q = text[i++];
        std::string value;
        while (i < n && text[i] != q) value += text[i++];
        if (i < n) ++i;
        return value;
    };
    auto skipBlanks = [&]() {
        while (i < n && (text[i] == ' ' || text[i] == '\t' || text[i] == '\r' || text[i] == '\n')) ++i;
    };

    while (i < n) {
        // Quoted strings and comments may hold anything, never parse them as directives.
        if (text[i] == '\'' || text[i] == '"') { readQuoted(); continue; }
        if (text[i] == '-' && i + 1 < n && text[i + 1] == '-') {
            size_t e = longBracketEnd(text, i + 2);
            if (e) { i = e; continue; }
            while (i < n && text[i] != '\n') ++i;
            continue;
        }
        size_t lb = longBracketEnd(text, i);
        if (lb) { i = lb; continue; }
        if (!isNameStart(text[i])) { ++i; continue; }

        size_t start = i;
        while (i < n && isNameChar(text[i])) ++i;
        std::string name = toLower(text.substr(start, i - start));
        if (name == "server_only") { manifest.serverOnly = true; continue; }
        Side directive = SideNone;
        if (name == "client_script" || name == "client_scripts") directive = SideClient;
        else if (name == "server_script" || name == "server_scripts") directive = SideServer;
        else if (name == "shared_script" || name == "shared_scripts") directive = SideBoth;
        else if (name == "files" || name == "file") directive = SideClient;
        if (directive == SideNone) continue;

        size_t depth = 0;
        Side side = directive;
        for (;;) {
            skipBlanks();
            if (i >= n) break;
            char c = text[i];
            if (c == '\'' || c == '"') { add(readQuoted(), side); continue; }
            if (c == '{') { ++i; ++depth; continue; }
            if (c == '[') {
                size_t e = longBracketEnd(text, i);
                if (e) { i = e; continue; }
                ++i;
                ++depth;
                continue;
            }
            if (c == '}' || c == ']') {
                if (depth == 0) break;
                ++i;
                if (--depth == 0) break;
                continue;
            }
            if (c == ',') { ++i; continue; }
            // A comment inside the list must not hide the entries that follow it.
            if (c == '-' && i + 1 < n && text[i + 1] == '-') {
                size_t e = longBracketEnd(text, i + 2);
                if (e) {
                    i = e;
                } else {
                    while (i < n && text[i] != '\n') ++i;
                }
                continue;
            }
            // At the top level any other token ends the directive's value; inside a
            // block a stray word is skipped so it cannot drop the remaining entries.
            if (depth == 0 || !isNameStart(c)) break;
            while (i < n && isNameChar(text[i])) ++i;
        }
    }
    return manifest;
}

std::string Decryptor::detectLuaType(const std::string& relFile,
                                     const LuaManifest& manifest) const {
    // server_only keeps the client from downloading anything, so the whole resource
    // is single-layer and every file takes the server key.
    if (manifest.serverOnly) return "server";
    std::string rel = normalizeRelPath(relFile);
    // An explicit server_script outranks a files membership; a shared script sits in
    // both sets, and the client side is the one that also gets the assets, so a
    // shared script is treated as client side.
    if (matchesManifestSet(manifest.serverScriptFiles, rel)) return "server";
    if (matchesManifestSet(manifest.clientFiles, rel)) return "client";
    if (matchesManifestSet(manifest.serverFiles, rel)) return "server";
    return "unknown";
}

void Decryptor::processLuaFile(const std::vector<uint8_t>& buf, const std::string& outPath,
                               const std::string& resourceName, const std::string& relFile) {
    std::string tmpPath = tempDir + "/" + resourceName + "/" + relFile + "c";
    writeFileBytes(tmpPath, buf);

    // Resolve the jar relative to cwd or the exe's project dir (running from
    // build/Release must still find Tools/Decompile/unluac54.jar).
    std::string jar = resolveTool("Tools/Decompile/unluac54.jar");
    std::string tmpWin = tmpPath;
    std::replace(tmpWin.begin(), tmpWin.end(), '/', '\\');
    std::string jarWin = jar;
    std::replace(jarWin.begin(), jarWin.end(), '/', '\\');
    std::string cmd = "java -jar \"" + jarWin + "\" \"" + tmpWin + "\"";
    std::string stdoutContent;
    const size_t maxOutput = 64u * 1024u * 1024u;
    bool overflow = false;
    int rc = -1;
    if (FILE* pipe = _popen(cmd.c_str(), "r")) {
        char buffer[4096];
        while (fgets(buffer, sizeof(buffer), pipe)) {
            if (stdoutContent.size() < maxOutput) stdoutContent += buffer;
            else overflow = true;
        }
        rc = _pclose(pipe);
    }

    if (overflow) {
        LOG("Lua decompilation FAILED for " + relFile + " (unluac output exceeds 64 MB)",
            LogLevel::WARNING);
        ++failed_;
        return;
    }

    fs::path p(outPath);
    if (p.has_parent_path()) fs::create_directories(p.parent_path());

    if (rc != 0) {
        std::string errfile = p.parent_path().string() + "/error_" + p.stem().string() + "_unluac.txt";
        writeTextFile(errfile, stdoutContent.empty() ? "Unknown unluac error" : stdoutContent);
        LOG("Lua decompilation FAILED for " + relFile, LogLevel::WARNING);
        ++failed_;
    } else {
        writeTextFile(outPath, stdoutContent);
        LOG("Lua decompiled: " + relFile, LogLevel::INFO);
        ++decryptedOk_;
    }
}

void Decryptor::decryptResourceFile(const std::string& resourcePath, const std::string& relFile,
                                    const std::vector<uint8_t>& decryptKey,
                                    const std::string& resourceName,
                                    const std::vector<uint8_t>& altKey,
                                    const LuaManifest& manifest) {
    std::string fullPath = resourcePath + "/" + relFile;
    std::string outputPath = outputDir + "/" + resourceName + "/" + relFile;
    if (!fs::exists(fullPath)) return;

    // not encrypted: copy
    if (!verifyEncrypted(fullPath)) {
        std::error_code ec;
        fs::create_directories(fs::path(outputPath).parent_path(), ec);
        fs::copy_file(fullPath, outputPath,
                      fs::copy_options::overwrite_existing, ec);
        if (!ec) ++copied_; else ++failed_;
        return;
    }

    try {
        auto stage1 = decryptFile(fullPath, DEFAULT_KEY);
        if (stage1.empty()) { LOG("Initial decryption failed: " + relFile, LogLevel::WARNING); ++failed_; return; }

        if (endsWith(toLower(relFile), ".lua")) {
            std::string luaType = detectLuaType(relFile, manifest);
            const std::vector<uint8_t>& firstKey = (luaType == "client" && !altKey.empty())
                                                       ? altKey : decryptKey;
            std::vector<uint8_t> dec = decryptBuffer(stage1, firstKey);
            if (hasLuaHeader(dec)) {
                processLuaFile(dec, outputPath, resourceName, relFile);
                return;
            }
            // alt offsets
            if (stage1.size() > 90) {
                std::vector<uint8_t> iv(stage1.begin() + 78, stage1.begin() + 90);
                std::vector<uint8_t> enc(stage1.begin() + 90, stage1.end());
                try {
                    auto alt = chacha20Xor(decryptKey, iv, enc);
                    if (hasLuaHeader(alt)) {
                        processLuaFile(alt, outputPath, resourceName, relFile);
                        return;
                    }
                } catch (...) {}
            }
            if (!altKey.empty()) {
                auto alt2 = decryptBuffer(stage1, altKey);
                if (hasLuaHeader(alt2)) {
                    processLuaFile(alt2, outputPath, resourceName, relFile);
                    return;
                }
            }

            // No key produced a Lua header: the classification or the grants are
            // wrong and nothing may be written out as unverified garbage.
            LOG("No valid Lua header for " + relFile + " - key mismatch, file skipped",
                LogLevel::WARNING);
            ++failed_;
            // Evidence: the encrypted input is the only copy of this data, so it is
            // kept next to where the output would have been instead of being lost.
            std::string rawPath = outputPath + ".raw";
            std::error_code ec;
            fs::create_directories(fs::path(rawPath).parent_path(), ec);
            auto raw = readFileBytes(fullPath);
            if (raw && writeFileBytes(rawPath, *raw))
                LOG("Nyers titkositott masolat kiirva: " + rawPath, LogLevel::WARNING);
            else
                LOG("Nyers titkositott masolat nem irhato: " + rawPath, LogLevel::WARNING);
        } else {
            auto dec = decryptBuffer(stage1, decryptKey);
            if (dec.empty()) { LOG("Buffer decryption failed: " + relFile, LogLevel::WARNING); ++failed_; return; }
            writeFileBytes(outputPath, dec);
            ++decryptedOk_;
        }
    } catch (const std::exception& e) {
        LOG("Decrypt error " + relFile + ": " + e.what(), LogLevel::WARNING);
        ++failed_;
    }
}

void Decryptor::decryptResource(const std::string& resourcePath, const std::string& resourceName,
                                const std::string& grantsToken) {
    LOG("Processing resource: " + resourceName, LogLevel::INFO);

    std::string fxapPath = resourcePath + "/.fxap";
    if (!fs::exists(fxapPath)) {
        // copy all
        std::error_code itErr;
        std::vector<fs::path> files;
        for (auto& e : fs::recursive_directory_iterator(resourcePath, itErr))
            if (e.is_regular_file()) files.push_back(e.path());
        if (itErr) {
            LOG(resourceName + ": figyelmeztetes - a konyvtarbejaras hiba miatt megszakadt: " +
                itErr.message() + " - a fajlalista reszleges", LogLevel::WARNING);
            ++failed_;
        }
        ProgressBar bar("  " + resourceName, files.size());
        for (auto& f : files) {
            std::string rel = std::filesystem::relative(f, resourcePath).generic_string();
            std::string out = outputDir + "/" + resourceName + "/" + rel;
            std::error_code ec;
            fs::create_directories(fs::path(out).parent_path(), ec);
            fs::copy_file(f, out, fs::copy_options::overwrite_existing, ec);
            if (!ec) ++copied_; else ++failed_;
            bar.tick();
        }
        bar.finish();
        return;
    }

    auto fxapBuf = decryptFile(fxapPath, DEFAULT_KEY);
    if (fxapBuf.empty()) { LOG("Unable to decrypt .fxap for " + resourceName, LogLevel::WARNING); return; }
    if (fxapBuf.size() < 78) { LOG("Truncated .fxap for " + resourceName, LogLevel::WARNING); return; }
    uint32_t resourceId = be32(fxapBuf.data() + 74);

    std::string idStr = std::to_string(resourceId);
    if (grantsMap_.find(idStr) == grantsMap_.end()) {
        LOG("No grant for " + resourceName + " - copying as-is", LogLevel::WARNING);
        std::error_code itErr;
        std::vector<fs::path> files;
        for (auto& e : fs::recursive_directory_iterator(resourcePath, itErr))
            if (e.is_regular_file() && e.path().filename() != ".fxap") files.push_back(e.path());
        if (itErr) {
            LOG(resourceName + ": figyelmeztetes - a konyvtarbejaras hiba miatt megszakadt: " +
                itErr.message() + " - a fajlalista reszleges", LogLevel::WARNING);
            ++failed_;
        }
        ProgressBar bar("  " + resourceName, files.size());
        for (auto& f : files) {
            std::string rel = fs::relative(f, resourcePath).generic_string();
            std::string out = outputDir + "/" + resourceName + "/" + rel;
            std::error_code ec;
            fs::create_directories(fs::path(out).parent_path(), ec);
            fs::copy_file(f, out, fs::copy_options::overwrite_existing, ec);
            if (!ec) ++copied_; else ++failed_;
            bar.tick();
        }
        bar.finish();
        return;
    }

    auto keyHex = grantsMap_[idStr].first;
    auto clkHex = grantsMap_[idStr].second;
    std::vector<uint8_t> decryptKey = hexDecode(keyHex);
    if (decryptKey.size() != 32) {
        LOG("Invalid grant key for " + resourceName + ": expected 32 bytes, got " +
            std::to_string(decryptKey.size()) + " - resource skipped", LogLevel::WARNING);
        ++failed_;
        return;
    }
    std::vector<uint8_t> altKey;
    if (!clkHex.empty()) {
        std::vector<uint8_t> clk = hexDecode(clkHex);
        if (clk.size() < 32) {
            LOG("Invalid grants_clk for " + resourceName + ": expected at least 32 bytes, got " +
                std::to_string(clk.size()) + " - alt key disabled", LogLevel::WARNING);
        } else {
            std::vector<uint8_t> iv(clk.begin(), clk.begin() + 16);
            std::vector<uint8_t> enc(clk.begin() + 16, clk.end());
            // The server ships grants_clk unpadded: the iv plus exactly two ciphertext
            // blocks. PKCS#7 stripping on such a value silently eats the tail of the key
            // whenever the last bytes happen to look padded, so the raw result is taken
            // first and the padded variant is only a fallback for a server that would pad.
            bool ok = aesCbc256DecryptRaw(AES_KEY, iv, enc, altKey) && altKey.size() == 32;
            size_t rawLen = altKey.size();
            size_t paddedLen = 0;
            if (!ok) {
                altKey.clear();
                std::vector<uint8_t> padded;
                if (aesCbc256DecryptPkcs7(AES_KEY, iv, enc, padded) && padded.size() == 32) {
                    altKey = std::move(padded);
                    ok = true;
                } else {
                    paddedLen = padded.size();
                }
            }
            if (!ok) {
                std::string obtained;
                if (rawLen || paddedLen)
                    obtained = "a visszakulcsolt kulcs (nyers/PKCS#7) " + std::to_string(rawLen) +
                               "/" + std::to_string(paddedLen) + " bajt";
                else
                    obtained = "a kulcs visszakulcsolasa nem sikerult";
                LOG("grants_clk nem hasznalhato a " + resourceName + " eroforrashoz: " +
                    std::to_string(clk.size()) + " bajt, " + obtained +
                    " - alternativ kulcs tiltva", LogLevel::WARNING);
                altKey.clear();
            }
        }
    }

    // Gather non-fxap files
    std::error_code itErr;
    std::vector<fs::path> files;
    for (auto& e : fs::recursive_directory_iterator(resourcePath, itErr))
        if (e.is_regular_file() && e.path().filename() != ".fxap") files.push_back(e.path());
    if (itErr) {
        LOG(resourceName + ": figyelmeztetes - a konyvtarbejaras hiba miatt megszakadt: " +
            itErr.message() + " - a fajlalista reszleges", LogLevel::WARNING);
        ++failed_;
    }

    // Read and classify the manifest once, before the pool starts: the workers only read it.
    const LuaManifest luaManifest = parseLuaManifest(resourcePath);

    ProgressBar bar("  " + resourceName, files.size());
    std::atomic<size_t> next{0};
    int workers = 6;
    std::vector<std::thread> pool;
    for (int w = 0; w < workers; ++w) {
        pool.emplace_back([&]() {
            for (;;) {
                size_t i = next.fetch_add(1);
                if (i >= files.size()) break;
                std::string rel;
                try {
                    rel = fs::relative(files[i], resourcePath).generic_string();
                    decryptResourceFile(resourcePath, rel, decryptKey, resourceName, altKey,
                                        luaManifest);
                } catch (const std::exception& e) {
                    LOG("File error (" + rel + "): " + std::string(e.what()), LogLevel::WARNING);
                    ++failed_;
                } catch (...) {
                    LOG("File error (" + rel + "): unknown exception while processing a file of " +
                        resourceName, LogLevel::WARNING);
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

    // ---- Fast detection: does ANY resource carry a .fxap marker? ----
    bool anyEncrypted = false;
    for (auto& d : dirs) {
        std::error_code ec;
        if (fs::exists(fs::path(d) / ".fxap", ec)) { anyEncrypted = true; break; }
    }

    if (!anyEncrypted) {
        // Nothing is encrypted: don't load grants, don't touch files, don't run
        // any crypto. Move the already-decrypted resource folders to Output as-is
        // (fs::rename = instant metadata move; per-file copy is only a fallback).
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
                fs::rename(d, dest, ec);           // same-volume move: instant
            }
            if (ec) {  // rename not possible (cross-volume / existing dest) -> copy
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

    // ---- Encrypted resources present: full grants + FXAP decryption path ----
    if (!loadGrants()) { ++failed_; return false; }

    LOG("Found " + std::to_string(dirs.size()) + " resource(s) to process", LogLevel::INFO);

    for (auto& d : dirs) {
        decryptResource(d, fs::path(d).filename().string(), "");
    }

    LOG("Decryption stats - ok:" + std::to_string(decryptedOk_.load()) +
        " copied:" + std::to_string(copied_.load()) + " failed:" + std::to_string(failed_.load()),
        LogLevel::SUCCESS);
    return failed_ == 0;
}

} // namespace fivem
