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
static const std::string LUA_HEADER_HEX = "1b4c7561540019930d0a1a0a040808785";

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

std::string Decryptor::detectLuaType(const std::string& resourcePath,
                                     const std::string& relFile) const {
    std::string manifest = resourcePath + "/fxmanifest.lua";
    if (!fs::exists(manifest)) manifest = resourcePath + "/__resource.lua";
    auto data = readFileBytes(manifest);
    if (!data) return "unknown";
    std::string text = toLower(std::string(data->begin(), data->end()));
    std::string rel = toLower(relFile);
    if (text.find(rel) == std::string::npos) return "unknown";
    if (text.find("client_script") != std::string::npos) return "client";
    if (text.find("server_script") != std::string::npos) return "server";
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
    int rc = -1;
    if (FILE* pipe = _popen(cmd.c_str(), "r")) {
        char buffer[4096];
        while (fgets(buffer, sizeof(buffer), pipe)) stdoutContent += buffer;
        rc = _pclose(pipe);
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
                                    const std::vector<uint8_t>& altKey) {
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
            std::string luaType = detectLuaType(resourcePath, relFile);
            std::vector<uint8_t> dec = decryptBuffer(stage1,
                luaType == "client" ? altKey : decryptKey);

            // Check Lua 5.4 header by hex-prefix match (same as python)
            bool isLua = false;
            if (dec.size() >= (LUA_HEADER_HEX.size() + 1) / 2) {
                std::string hex = hexEncode(std::vector<uint8_t>(
                    dec.begin(), dec.begin() + (LUA_HEADER_HEX.size() + 1) / 2));
                isLua = hex.rfind(LUA_HEADER_HEX, 0) == 0;
            }
            if (isLua) {
                processLuaFile(dec, outputPath, resourceName, relFile);
                return;
            }
            // alt offsets
            if (stage1.size() > 90) {
                std::vector<uint8_t> iv(stage1.begin() + 78, stage1.begin() + 90);
                std::vector<uint8_t> enc(stage1.begin() + 90, stage1.end());
                try {
                    auto alt = chacha20Xor(decryptKey, iv, enc);
                    if (!alt.empty()) { processLuaFile(alt, outputPath, resourceName, relFile); return; }
                } catch (...) {}
            }
            auto alt2 = decryptBuffer(stage1, altKey);
            if (!alt2.empty()) { processLuaFile(alt2, outputPath, resourceName, relFile); return; }

            // fallback raw
            writeFileBytes(outputPath, dec);
            ++decryptedOk_;
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
        std::vector<fs::path> files;
        for (auto& e : fs::recursive_directory_iterator(resourcePath))
            if (e.is_regular_file()) files.push_back(e.path());
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
        std::vector<fs::path> files;
        for (auto& e : fs::recursive_directory_iterator(resourcePath))
            if (e.is_regular_file() && e.path().filename() != ".fxap") files.push_back(e.path());
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
    std::vector<uint8_t> altKey;
    if (!clkHex.empty()) {
        std::vector<uint8_t> clk = hexDecode(clkHex);
        if (clk.size() > 16) {
            std::vector<uint8_t> iv(clk.begin(), clk.begin() + 16);
            std::vector<uint8_t> enc(clk.begin() + 16, clk.end());
            if (enc.size() % 16 == 0) {
                aesCbc256DecryptPkcs7(AES_KEY, iv, enc, altKey);
            }
        }
    }

    // Gather non-fxap files
    std::vector<fs::path> files;
    for (auto& e : fs::recursive_directory_iterator(resourcePath))
        if (e.is_regular_file() && e.path().filename() != ".fxap") files.push_back(e.path());

    ProgressBar bar("  " + resourceName, files.size());
    std::atomic<size_t> next{0};
    std::mutex mtx;
    int workers = 6;
    std::vector<std::thread> pool;
    for (int w = 0; w < workers; ++w) {
        pool.emplace_back([&]() {
            for (;;) {
                size_t i = next.fetch_add(1);
                if (i >= files.size()) break;
                std::string rel = fs::relative(files[i], resourcePath).generic_string();
                try { decryptResourceFile(resourcePath, rel, decryptKey, resourceName, altKey); }
                catch (const std::exception& e) { LOG("File error: " + std::string(e.what()), LogLevel::WARNING); }
                bar.tick();
            }
        });
    }
    for (auto& t : pool) t.join();
    bar.finish();
}

void Decryptor::runAll() {
    if (!fs::exists(unpackedDir)) {
        LOG("No Unpacked/ directory found - run the dumper first.", LogLevel::ERROR);
        return;
    }

    std::vector<std::string> dirs;
    for (auto& e : fs::directory_iterator(unpackedDir))
        if (e.is_directory()) dirs.push_back(e.path().generic_string());
    std::sort(dirs.begin(), dirs.end());

    if (dirs.empty()) {
        LOG("Nothing to process.", LogLevel::INFO);
        return;
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
                for (auto& f : fs::recursive_directory_iterator(dest))
                    if (f.is_regular_file()) ++fileCount;
            } else {
                LOG("Move failed for " + name + ": " + ec.message(), LogLevel::ERROR);
                ++failed_;
            }
        }
        copied_ = (int)fileCount;
        LOG("Moved " + std::to_string(moved) + " resource(s) (" + std::to_string(fileCount) +
            " files) directly to Output - no decryption needed", LogLevel::SUCCESS);
        return;
    }

    // ---- Encrypted resources present: full grants + FXAP decryption path ----
    if (!loadGrants()) return;

    LOG("Found " + std::to_string(dirs.size()) + " resource(s) to process", LogLevel::INFO);
    decryptedOk_ = failed_ = copied_ = 0;

    for (auto& d : dirs) {
        decryptResource(d, fs::path(d).filename().string(), "");
    }

    LOG("Decryption stats - ok:" + std::to_string(decryptedOk_) +
        " copied:" + std::to_string(copied_) + " failed:" + std::to_string(failed_),
        LogLevel::SUCCESS);
}

} // namespace fivem
