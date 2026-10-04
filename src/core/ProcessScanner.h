#pragma once
#include <string>
#include <vector>
#include <cstdint>
namespace fivem {
struct ProcessInfo {
    uint32_t pid;
    std::string name;
};
std::string findFiveMToken();
std::vector<std::string> findIpsInMemory();
void saveServerName(const std::string& ip, const std::string& name);
std::string getCachedServerName(const std::string& ip);
std::vector<ProcessInfo> getFiveMProcesses();
std::vector<ProcessInfo> getGtaProcesses();
}
