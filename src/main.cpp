#include <windows.h>
#include <iostream>
#include <string>
#include <cstdlib>
#include <memory>
#include <future>
#include <vector>
#include <filesystem>

#include "core/Logger.h"
#include "core/Bundler.h"
#include "core/Checkpoint.h"
#include "core/ProcessScanner.h"
#include "core/HttpClient.h"
#include "dumper/FiveMDumper.h"
#include "dumper/Decryptor.h"
#include "utils/Str.h"
#include "utils/Term.h"
#include "utils/Json.h"

namespace fs = std::filesystem;

using namespace fivem;

static const char* TEST_SERVER_IP = "play.popcornrp.city:30120";

// Read a line, returning false on EOF (non-interactive).
static bool readLine(std::string& out) {
    if (!std::getline(std::cin, out)) return false;
    return true;
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    fivem::term::enableColors();

    if (getenv("DUMPER_SELFPATH")) {
        std::string err;
        bool ok = fivem::ensurePayload(err);
        std::cout << "payload: " << (ok ? "OK" : ("HIBA: " + err)) << "\n";
        std::cout << "Unpacker: " << resolveTool("Bin/Unpacker.exe") << "\n";
        std::cout << "Jar:      " << resolveTool("Tools/Decompile/unluac54.jar") << "\n";
        return 0;
    }

    std::cout << CLR(term::CYAN) << "==============================================\n";
    std::cout << "   FiveM Dumper C++ v1.0 - AllInOne\n";
    std::cout << "==============================================" << CLR(term::RESET) << "\n";
    std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET) << " Parsing Server Info...\n";

    bool testMode = getenv("DUMPER_TEST_MODE") != nullptr;

    // ---- Token ----
    std::string token;
    const char* envToken = getenv("DUMPER_TOKEN");
    if (envToken && *envToken) {
        token = envToken;
        std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET) << " Using token from DUMPER_TOKEN env var.\n";
    } else {
        token = findFiveMToken();
    }
    if (token.empty()) {
        if (!testMode) {
            std::cerr << CLR(term::RED) << "Error: Token not found. Make sure FiveM is running "
                         "and connected to the server. Run as administrator." << CLR(term::RESET) << "\n";
            return 1;
        }
        std::cerr << CLR(term::RED) << "Error: Token not found in test mode. Set DUMPER_TOKEN." << CLR(term::RESET) << "\n";
        return 1;
    }
    if (!token.empty()) {
        auto nl = token.find_first_of("\r\n");
        if (nl != std::string::npos) token = token.substr(0, nl);
        token = trim(token);
    }

    // ---- Server IP ----
    std::string ip, serverName, baseUrl;
    const char* envIp = getenv("DUMPER_SERVER_IP");
    std::vector<std::string> ips;
    bool ipsScanned = false;

    Checkpoint checkpoint;
    checkpoint.load();
    std::unique_ptr<FiveMDumper> dumper;  // single config fetch, reused for validation + run
    const char* envName = getenv("DUMPER_SERVER_NAME");

    for (;;) {
        // Build a candidate IP
        if (testMode) {
            ip = (envIp && *envIp) ? envIp : TEST_SERVER_IP;
            std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET) << " TEST MODE: Using IP " << ip << "\n";
        } else {
            if (!ipsScanned) {
                std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET) << " Scanning GTAProcess processes for all IPs...\n";
                ips = findIpsInMemory();
                ipsScanned = true;
            }
            if (ips.empty()) {
                std::cout << CLR(term::YELLOW) << "[!]" << CLR(term::RESET) << " No IP found in memory. Enter IP (ip:port): ";
                std::string in;
                if (!readLine(in) || trim(in).empty()) {
                    std::cerr << CLR(term::RED) << "No server IP provided." << CLR(term::RESET) << "\n"; return 1;
                }
                ip = trim(in);
            } else {
                std::cout << "\n" << CLR(term::GREEN) << "[+]" << CLR(term::RESET)
                          << " Found " << ips.size() << " IP(s) in memory:\n";
                std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET) << " Servernevek lekérdezése (/dynamic.json)...\n";
                std::vector<std::future<std::string>> nameProbes;
                nameProbes.reserve(ips.size());
                for (auto& candidate : ips) {
                    std::string cached = getCachedServerName(candidate);
                    if (!cached.empty() && cached != candidate) {
                        nameProbes.push_back(std::async(std::launch::deferred, [candidate, cached]() { return cached; }));
                    } else {
                        std::string url = "http://" + candidate;
                        nameProbes.push_back(std::async(std::launch::async,
                            [url]() { return FiveMDumper::probeDynamicHostname(url, 3000); }));
                    }
                }
                std::cout << CLR(term::DIM) << std::string(60, '-') << CLR(term::RESET) << "\n";
                for (size_t i = 0; i < ips.size(); ++i) {
                    std::string name = nameProbes[i].get();
                    if (!name.empty() && name != getCachedServerName(ips[i])) saveServerName(ips[i], name);
                    std::cout << "  " << CLR(term::CYAN) << "[" << (i + 1) << "]" << CLR(term::RESET) << " " << ips[i];
                    if (!name.empty()) std::cout << "  " << CLR(term::GREEN) << "(" << name << ")" << CLR(term::RESET);
                    std::cout << "\n";
                }
                std::cout << "  " << CLR(term::CYAN) << "[0]" << CLR(term::RESET) << " Manual IP entry\n"
                          << CLR(term::DIM) << std::string(60, '-') << CLR(term::RESET) << "\n";
                std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET) << " Choose IP (number) or type ip:port: ";
                std::string choice;
                if (!readLine(choice)) {  // EOF -> first IP
                    ip = ips[0];
                    std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET) << " Non-interactive, using first IP.\n";
                } else {
                    choice = trim(choice);
                    bool isNum = !choice.empty() &&
                                 choice.find_first_not_of("0123456789") == std::string::npos;
                    if (isNum && std::stoi(choice) >= 1 && std::stoi(choice) <= (int)ips.size()) {
                        ip = ips[std::stoi(choice) - 1];
                    } else if (choice == "0" || choice.empty()) {
                        std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET) << " Enter server IP (ip:port): ";
                        std::string in;
                        if (!readLine(in) || trim(in).empty()) {
                            std::cerr << CLR(term::RED) << "No server IP provided." << CLR(term::RESET) << "\n"; return 1;
                        }
                        ip = trim(in);
                    } else {
                        ip = choice;  // typed ip:port or hostname:port
                    }
                }
            }
        }
        if (ip.empty()) { std::cerr << CLR(term::RED) << "No server IP." << CLR(term::RESET) << "\n"; return 1; }
        // clean protocol/slash
        if (startsWith(ip, "https://")) ip = ip.substr(8);
        else if (startsWith(ip, "http://")) ip = ip.substr(7);
        while (!ip.empty() && ip.back() == '/') ip.pop_back();

        baseUrl = "http://" + ip;
        std::cout << CLR(term::GREEN) << "[+]" << CLR(term::RESET) << " Selected server IP: " << ip << "\n";

        // ---- Validate + fetch server name in ONE config call ----
        dumper = std::make_unique<FiveMDumper>(baseUrl, token, "", checkpoint);
        if (dumper->getConfiguration()) {
            // The /client endpoint does not expose a display name (only resources/
            // grants/fileServer), so the name comes from: config hostname -> env ->
            // anonymous /dynamic.json -> cache -> user prompt. Folder naming stays
            // stable across runs via cache.
            serverName = dumper->hostname();
            if (serverName.empty() && envName && *envName) serverName = envName;
            if (serverName.empty()) {
                std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET) << " Szervernev lekerese a /dynamic.json vegpontbol...\n";
                if (dumper->fetchDynamicHostname()) {
                    serverName = dumper->hostname();
                }
            }
            std::string cached = getCachedServerName(ip);
            if (serverName.empty() && !cached.empty() && cached != ip) serverName = cached;
            if (serverName.empty() && !testMode) {
                std::cout << CLR(term::YELLOW) << "[?]" << CLR(term::RESET) << " Adj nevet a szervernek (mappanév, Enter = IP): ";
                std::string in;
                if (readLine(in) && !trim(in).empty()) serverName = trim(in);
            }
            if (serverName.empty()) serverName = ip;
            saveServerName(ip, serverName);
            dumper->setServerName(serverName);  // dirs follow the real name now
            std::cout << CLR(term::GREEN) << "[+]" << CLR(term::RESET) << " Server Name: "
                      << CLR(term::BOLD) << serverName << CLR(term::RESET) << "\n";
            break;
        }

        std::string cached = getCachedServerName(ip);
        std::cout << CLR(term::YELLOW) << "[!] Ez az IP nem valaszol a /client vegponton"
                  << (cached.empty() ? "" : (" (utoljara: " + cached + ")")) << ".\n";
        std::cout << "    Ellenorizd, hogy a jatek Csatlakoztatva van ehhez a szerverhez." << CLR(term::RESET) << "\n\n";

        if (testMode) {
            std::cerr << CLR(term::RED) << "Test-mode server unreachable; aborting." << CLR(term::RESET) << "\n";
            return 1;
        }
    }

    std::string filterRes = testMode
        ? std::string(getenv("DUMPER_RESOURCE") ? getenv("DUMPER_RESOURCE") : "pma-voice")
        : "";

    if (!checkpoint.completed_resources.empty()) {
        std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET) << " Found checkpoint: "
                  << checkpoint.completed_resources.size()
                  << " resources already completed. Resuming...\n";
    }

    std::cout << "\n" << CLR(term::BOLD) << CLR(term::CYAN) << "--- PHASE 1: Download ---" << CLR(term::RESET) << "\n";
    if (!dumper->run(filterRes)) {
        std::cerr << CLR(term::RED) << "Download phase failed." << CLR(term::RESET) << "\n";
        return 1;
    }

    // ---- Decrypt ----
    std::cout << "\n" << CLR(term::BOLD) << CLR(term::CYAN) << "--- PHASE 2: Decrypt ---" << CLR(term::RESET) << "\n";
    Decryptor decryptor(dumper->serverDir);
    decryptor.runAll();

    std::cout << "\n" << CLR(term::GREEN)
              << "==============================================\n";
    std::cout << " Done! Output: Servers/" << dumper->serverDir << "/Output\n";
    std::cout << "==============================================" << CLR(term::RESET) << "\n";

    // ---- Cleanup temp dirs ----
    std::error_code ec;
    fs::remove_all("Servers/" + dumper->serverDir + "/Temp", ec);
    fs::remove_all("Servers/" + dumper->serverDir + "/TempCompiled", ec);
    fs::remove_all("Servers/" + dumper->serverDir + "/Unpacked", ec);

    return 0;
}
