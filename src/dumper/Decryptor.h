#pragma once

#include <atomic>
#include <string>
#include <vector>
#include <map>
#include <set>

namespace fivem {

class Decryptor {
public:
    explicit Decryptor(std::string serverDir);

    // Decrypt all resources found under Servers/<dir>/Unpacked.
    void runAll();

    std::string outputDir;
    std::string tempDir;
    std::string unpackedDir;

private:
    // Per-resource manifest classification: normalised (lowercase, '/'-separated)
    // relative paths of the scripts delivered to the client and to the server.
    // Entries keep the manifest's own globs, which detectLuaType matches as well.
    // serverScriptFiles holds the paths named by an explicit server_script, which
    // outrank a files membership; serverOnly marks a resource with no client side.
    struct LuaManifest {
        std::set<std::string> clientFiles;
        std::set<std::string> serverFiles;
        std::set<std::string> serverScriptFiles;
        bool serverOnly = false;
    };

    void decryptResource(const std::string& resourcePath, const std::string& resourceName,
                         const std::string& grantsToken);
    void decryptResourceFile(const std::string& resourcePath, const std::string& relFile,
                             const std::vector<uint8_t>& decryptKey, const std::string& resourceName,
                             const std::vector<uint8_t>& altKey, const LuaManifest& manifest);
    bool verifyEncrypted(const std::string& path) const;
    std::vector<uint8_t> decryptFile(const std::string& path, const std::vector<uint8_t>& key) const;
    std::vector<uint8_t> decryptBuffer(const std::vector<uint8_t>& data,
                                       const std::vector<uint8_t>& key) const;
    static LuaManifest parseLuaManifest(const std::string& resourcePath);
    std::string detectLuaType(const std::string& relFile, const LuaManifest& manifest) const;
    void processLuaFile(const std::vector<uint8_t>& buf, const std::string& outPath,
                        const std::string& resourceName, const std::string& relFile);

    std::string serverDir_;
    std::map<std::string, std::pair<std::string, std::string>> grantsMap_;  // id -> (key_hex, clk_hex)
    bool loadGrants();

    std::atomic<int> decryptedOk_{0}, failed_{0}, copied_{0};
};

} // namespace fivem
