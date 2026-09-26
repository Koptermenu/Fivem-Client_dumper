#pragma once

#include <atomic>
#include <string>
#include <vector>
#include <map>

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
    void decryptResource(const std::string& resourcePath, const std::string& resourceName,
                         const std::string& grantsToken);
    void decryptResourceFile(const std::string& resourcePath, const std::string& relFile,
                             const std::vector<uint8_t>& decryptKey, const std::string& resourceName,
                             const std::vector<uint8_t>& altKey);
    bool verifyEncrypted(const std::string& path) const;
    std::vector<uint8_t> decryptFile(const std::string& path, const std::vector<uint8_t>& key) const;
    std::vector<uint8_t> decryptBuffer(const std::vector<uint8_t>& data,
                                       const std::vector<uint8_t>& key) const;
    std::string detectLuaType(const std::string& resourcePath, const std::string& relFile) const;
    void processLuaFile(const std::vector<uint8_t>& buf, const std::string& outPath,
                        const std::string& resourceName, const std::string& relFile);

    std::string serverDir_;
    std::map<std::string, std::pair<std::string, std::string>> grantsMap_;  // id -> (key_hex, clk_hex)
    bool loadGrants();

    std::atomic<int> decryptedOk_{0}, failed_{0}, copied_{0};
};

} // namespace fivem
