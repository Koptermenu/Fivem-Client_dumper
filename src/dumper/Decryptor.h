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
    bool runAll();
    std::string outputDir;
    std::string tempDir;
    std::string unpackedDir;
private:
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
    std::map<std::string, std::pair<std::string, std::string>> grantsMap_;
    bool loadGrants();
    std::atomic<int> decryptedOk_{0}, failed_{0}, copied_{0};
};
} 