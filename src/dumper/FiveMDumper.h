#pragma once
#include <string>
#include <vector>
#include <map>
#include "../core/HttpClient.h"
#include "../core/Checkpoint.h"
#include "../utils/Json.h"
namespace fivem {
struct FileEntry {
    std::string name;
    std::string hash;
};
struct ResourceInfo {
    std::string name;
    std::string uri;
    std::string fileServer;
    std::vector<FileEntry> files;
    std::vector<FileEntry> streamFiles;
};
class FiveMDumper {
public:
    FiveMDumper(std::string baseUrl, std::string token,
                std::string serverName, Checkpoint& checkpoint);
    bool getConfiguration();
    bool loadConfigFile(const std::string& path);
    bool loadCachedConfiguration();
    static bool findCachedConfig(const std::string& baseUrl, std::string& outDir);
    bool configReady() const { return configFetched_; }
    bool usingCachedConfig() const { return usingCachedConfig_; }
    bool fetchDynamicHostname();
    static std::string probeDynamicHostname(const std::string& baseUrl, int timeoutMs);
    void fetchResource(const ResourceInfo& res);
    bool run(const std::string& filterResource = "");
    void setServerName(const std::string& name);
    const std::string& hostname() const { return hostname_; }
    std::string serverDir;
    std::string resourcesDir;
    std::string unpackedDir;
    std::string tempDir;
private:
    void downloadAndDecrypt(const std::string& url, const std::vector<uint8_t>& key,
                            const std::vector<uint8_t>& iv, const std::string& outPath,
                            const std::string& expectedChecksum,
                            const ByteProgress& onBytes = nullptr,
                            const SizeCallback& onStart = nullptr);
    bool downloadQuiet(const std::string& url, const std::vector<uint8_t>& key,
                       const std::vector<uint8_t>& iv, const std::string& outPath);
    bool unpackRpf(const std::string& rpfPath, const std::string& outDir);
    bool applyConfiguration(const Json& js);
    void saveConfigCache();
    void detectNewResources();
    bool fetchFromServerStore();
    void uploadToServerStore();
    std::string serverStoreUrl() const;
    std::string serverStoreKey() const;
    std::string baseUrl_;
    std::string token_;
    std::string serverName_;
    std::string hostname_;
    std::string grants_;
    std::string rawConfig_;
    bool configFetched_ = false;
    bool usingCachedConfig_ = false;
    HttpClient http_;
    Checkpoint& checkpoint_;
    std::vector<ResourceInfo> resources_;
    int maxWorkers_ = 24;
};
} 