#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace fivem {

class Decryptor {
public:
    explicit Decryptor(std::string serverDir);

    // Decrypt all resources found under Servers/<dir>/Unpacked.
    // Returns false if at least one file failed.
    bool runAll();

    std::string outputDir;
    std::string tempDir;
    std::string unpackedDir;

private:
    // One resource's key material, tried in order for every file of that resource.
    // The right key is per-file: the grants key decrypts some files and the derived
    // client key the others, so every candidate is attempted and the first one whose
    // plaintext validates wins.
    struct ResourceKeys {
        std::vector<std::vector<uint8_t>> candidates;
        std::string serverKeyHex;
        std::string clientKeyHex;
        bool serverKeyValid = false;
        bool clientKeyValid = false;
        std::string clientKeyError;
    };

    void decryptResource(const std::string& resourcePath, const std::string& resourceName);
    bool verifyEncrypted(const std::string& path) const;
    std::vector<uint8_t> decryptFile(const std::string& path, const std::vector<uint8_t>& key) const;
    ResourceKeys resolveKeys(uint32_t resourceId, const std::string& resourceName);
    void processLuaFile(const std::vector<uint8_t>& buf, const std::string& outPath,
                        const std::string& resourceName, const std::string& relFile);
    void decryptResourceFile(const std::string& resourcePath, const std::string& relFile,
                             const ResourceKeys& keys, const std::string& resourceName);

    std::string serverDir_;
    std::map<std::string, std::pair<std::string, std::string>> grantsMap_;  // id -> (key_hex, clk_hex)
    bool loadGrants();

    std::atomic<int> decryptedOk_{0}, failed_{0}, copied_{0};
};

} // namespace fivem