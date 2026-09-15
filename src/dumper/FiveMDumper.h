#pragma once

#include <string>
#include <vector>
#include <map>
#include "../core/HttpClient.h"
#include "../core/Checkpoint.h"

namespace fivem {

struct FileEntry {
    std::string name;      // relative file name within the resource
    std::string hash;      // expected checksum (raw encrypted bytes)
};

struct ResourceInfo {
    std::string name;
    std::string uri;       // "sha256#<base64>" style
    std::string fileServer;
    std::vector<FileEntry> files;
    std::vector<FileEntry> streamFiles;
};

class FiveMDumper {
public:
    FiveMDumper(std::string baseUrl, std::string token,
                std::string serverName, Checkpoint& checkpoint);

    // Fetch /client configuration and populate members. Returns resource list.
    bool getConfiguration();

    // Query the anonymous /dynamic.json endpoint for the display name
    // (sv_hostname), strip FX color markup and reject default placeholders.
    // Sets hostname_ on success. Returns true when a usable name was found.
    bool fetchDynamicHostname();

    // Download a single resource (files + streamFiles) into Unpacked/Temp dirs.
    void fetchResource(const ResourceInfo& res);

    // Full run: config + select + download all. filterResource: optional name filter (test mode).
    bool run(const std::string& filterResource = "");

    // Update server name (recomputes server dirs). Call after getConfiguration()
    // revealed the hostname; avoids a second config fetch.
    void setServerName(const std::string& name);

    // Hostname resolved from the last getConfiguration() (empty if none present).
    const std::string& hostname() const { return hostname_; }

    std::string serverDir;       // safe server folder name
    std::string resourcesDir;
    std::string unpackedDir;
    std::string tempDir;

private:
    // Download, verify checksum, decrypt, write. Throws std::runtime_error on failure.
    void downloadAndDecrypt(const std::string& url, const std::vector<uint8_t>& key,
                            const std::vector<uint8_t>& iv, const std::string& outPath,
                            const std::string& expectedChecksum,
                            const ByteProgress& onBytes = nullptr);

    // Best-effort fetch: GET once, ignore 404/decrypt errors, never throws.
    // Returns true if a file was written. Used to backfill fxmanifest when an RPF
    // could not be unpacked.
    bool downloadQuiet(const std::string& url, const std::vector<uint8_t>& key,
                       const std::vector<uint8_t>& iv, const std::string& outPath);

    // Unpack an RPF with Bin/Unpacker.exe (path resolved relative to exe dir too).
    // Returns true if new files appeared in outDir.
    bool unpackRpf(const std::string& rpfPath, const std::string& outDir);

    std::string baseUrl_;
    std::string token_;
    std::string serverName_;
    std::string hostname_;
    std::string grants_;
    bool configFetched_ = false;
    HttpClient http_;
    Checkpoint& checkpoint_;
    std::vector<ResourceInfo> resources_;
    std::vector<uint8_t> iv_;        // 8-byte ChaCha nonce (uri[53:61] of DECODED uri)
    std::vector<uint8_t> hmacKey_;   // 32-byte HMAC key (XOR of decoded uri[19:32+19] with 0x69)
    int maxWorkers_ = 24;
};

} // namespace fivem
