#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace fivem {

struct ProcessInfo {
    uint32_t pid;
    std::string name;
};

// Scan FiveM process memory for the CitizenFX token. Returns empty on failure.
std::string findFiveMToken();

// List all IP:port strings found in FiveM GTAProcess memory.
std::vector<std::string> findIpsInMemory();

// Server name cache (server_name.txt JSON: {"ip:port": "Name", ...})
void saveServerName(const std::string& ip, const std::string& name);
std::string getCachedServerName(const std::string& ip);

// Get all FiveM processes
std::vector<ProcessInfo> getFiveMProcesses();
std::vector<ProcessInfo> getGtaProcesses();

} // namespace fivem
