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
#include "ai/Cleanup.h"
#include "ai/LlmCleanup.h"
#include "utils/Str.h"
#include "utils/Term.h"
#include "utils/Json.h"
namespace fs = std::filesystem;
using namespace fivem;
static const char* TEST_SERVER_IP = "play.popcornrp.city:30120";
static bool readLine(std::string& out) {
    if (!std::getline(std::cin, out)) return false;
    return true;
}
static bool parseDigits(const std::string& s, unsigned long long& out) {
    if (s.empty() || s.size() > 18) return false;
    unsigned long long v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + static_cast<unsigned long long>(c - '0');
    }
    out = v;
    return true;
}
static bool askYesNo(const char* question, bool defaultYes) {
    std::cout << question << (defaultYes ? " [Y/n]: " : " [y/N]: ");
    std::string answer;
    if (!std::getline(std::cin, answer)) return defaultYes;
    answer = toLower(trim(answer));
    if (answer.empty()) return defaultYes;
    return answer == "y" || answer == "yes" || answer == "i";
}
static void runReadabilityPass(const std::string& serverRoot, bool testMode) {
    const std::string outputDir = serverRoot + "/Output";
    const std::string cleanDir = serverRoot + "/Output_clean";
    const std::string aiDir = serverRoot + "/Output_ai";
    std::error_code ec;
    if (!fs::is_directory(outputDir, ec)) return;
    const bool forceCleanup = getenv("DUMPER_CLEANUP") != nullptr;
    const bool forceLlm = getenv("DUMPER_LLM") != nullptr;
    bool wantCleanup = forceCleanup;
    if (!wantCleanup) {
        if (testMode) return;
        wantCleanup = askYesNo(
            "\nOlvashatosag javitas a dekodedolt .lua fajlokon? (determinisztikus, azonnal)",
            true);
    }
    if (!wantCleanup) return;
    std::cout << CLR(term::CYAN) << "\n[*]" << CLR(term::RESET) << " Strukturális tisztítás...\n";
    const CleanupStats cs = cleanupLuaTree(outputDir, cleanDir);
    std::cout << CLR(term::GREEN) << "[+]" << CLR(term::RESET) << " Tisztított Lua: " << cleanDir
              << " (" << cs.files << " fajl, " << cs.renamedVars << " atnevezés, "
              << cs.bannerRemoved << " banner, " << cs.reindentedLines << " sor indentálva)\n";
    if (cs.gotoLabels > 0) {
        std::cout << CLR(term::YELLOW) << "[!]" << CLR(term::RESET) << " " << cs.gotoLabels
                  << " goto/label blokk maradt: ezeket automata atalakitas nelkul nem bantjuk.\n";
    }
    if (cs.ambiguousVars > 0) {
        LOG("atnevezes kimaradt " + std::to_string(cs.ambiguousVars) +
            " valtozonak (nincs egyertelmű kotes vagy a nevet globalis foglalja)", LogLevel::INFO);
    }
    bool wantLlm = forceLlm;
    if (!wantLlm) {
        if (testMode) return;
        const char* want = getenv("DUMPER_LLM_MODEL");
        const LlmModel& m = llmModelById(want ? want : "coder");
        const uint64_t engineBytes = llmEngineDownloadBytes();
        const uint64_t total = m.size + engineBytes;
        const auto gb = [](uint64_t n) {
            return static_cast<double>(n) / (1024.0 * 1024.0 * 1024.0);
        };
        std::cout << "\n";
        std::cout << CLR(term::BOLD) << "AI-val atirjam a kodot?" << CLR(term::RESET) << "\n";
        std::cout << "    modell: " << m.displayName << " ("
                  << std::fixed << std::setprecision(2) << gb(m.size) << " GB)\n";
        std::cout << "    futtato: llama.cpp " << llmBackendName() << " ("
                  << std::fixed << std::setprecision(2) << gb(engineBytes) << " GB)\n";
        std::cout << "    osszesen: " << std::fixed << std::setprecision(2) << gb(total)
                  << " GB letoltes\n";
        std::cout << "    normalis GPU kell hozza, lehetoleg NVIDIA. Vulkan build 31 MB, "
                     "de lassabb.\n";
        std::cout << "    Ha a modell rossz kodot ad, a tisztitott fajl marad a helyen.\n";
        wantLlm = askYesNo("    Letoltes es futtatas?", false);
    }
    if (!wantLlm) return;
    std::string engine;
    std::string engErr;
    const ProgressFn dlProgress = [](uint64_t done, uint64_t total) {
        static uint64_t last = 0;
        if (done - last < (16u << 20)) return;
        last = done;
        std::cout << "\r  " << (done >> 20) << " / " << (total >> 20) << " MB" << std::flush;
    };
    if (!ensureEngine(!testMode, dlProgress, engine, engErr)) {
        std::cout << CLR(term::YELLOW) << "[!]" << CLR(term::RESET)
                  << " Futtato: " << engErr << "\n";
        return;
    }
    std::cout << "\n" << CLR(term::GREEN) << "[+]" << CLR(term::RESET) << " Futtato: " << engine
              << "\n";
    LlmOptions opts;
    opts.model = &llmModelById(getenv("DUMPER_LLM_MODEL") ? getenv("DUMPER_LLM_MODEL") : "coder");
    if (const char* v = getenv("DUMPER_LLM_TIMEOUT")) {
        const long s = strtol(v, nullptr, 10);
        if (s >= 10 && s <= 86400) {
            opts.totalTimeoutMs = static_cast<DWORD>(s) * 1000;
            opts.fileTimeoutMs = static_cast<DWORD>(s) * 1000;
        }
    }
    std::string modelPath;
    std::string err;
    if (!ensureModel(opts, !testMode,
                     [](uint64_t done, uint64_t total) {
                         (void)total;
                         static uint64_t last = 0;
                         if (done - last < (16u << 20)) return;
                         last = done;
                         std::cout << "\r  " << (done >> 20) << " / " << (total >> 20) << " MB"
                                   << std::flush;
                     },
                     modelPath, err)) {
        std::cout << CLR(term::YELLOW) << "[!]" << CLR(term::RESET) << " Modell: " << err << "\n";
        return;
    }
    std::cout << "\n";
    std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET) << " Nyelvi modell futtatása...\n";
    const LlmStats ls = llmRewriteTree(opts, cleanDir, aiDir, engine, modelPath,
                                       [](uint64_t done, uint64_t total) {
                                           std::cout << "\r  fajl " << done << " / " << total
                                                     << std::flush;
                                       });
    std::cout << "\n";
    std::cout << CLR(term::GREEN) << "[+]" << CLR(term::RESET) << " LLM kiemenet: " << aiDir
              << " (" << ls.rewritten << " atirva, " << ls.failed << " hibas, "
              << ls.skippedAlreadyClean << " mar tisztta, " << ls.skippedTooLarge << " tul nagy, "
              << ls.skippedOutOfTime << " idobudgetbol kimaradt)\n";
    std::cout << "    ido: " << (ls.elapsedMs / 1000) << " s / " << (opts.totalTimeoutMs / 1000)
              << " s keret\n";
    if (ls.rewritten < ls.files) {
        std::cout << CLR(term::YELLOW) << "[!]" << CLR(term::RESET)
                  << " A nem atirt fajlok a " << cleanDir << " mappaban maradtak.\n";
    }
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
    std::string ip, serverName, baseUrl;
    const char* envIp = getenv("DUMPER_SERVER_IP");
    std::vector<std::string> ips;
    bool ipsScanned = false;
    Checkpoint checkpoint;
    checkpoint.load();
    std::unique_ptr<FiveMDumper> dumper;
    const char* envName = getenv("DUMPER_SERVER_NAME");
    for (;;) {
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
                    if (!name.empty() && name != "ismeretlen" &&
                        name != getCachedServerName(ips[i])) {
                        saveServerName(ips[i], name);
                    }
                    std::cout << "  " << CLR(term::CYAN) << "[" << (i + 1) << "]" << CLR(term::RESET) << " " << ips[i];
                    if (!name.empty()) std::cout << "  " << CLR(term::GREEN) << "(" << name << ")" << CLR(term::RESET);
                    std::cout << "\n";
                }
                std::cout << "  " << CLR(term::CYAN) << "[0]" << CLR(term::RESET) << " Manual IP entry\n"
                          << CLR(term::DIM) << std::string(60, '-') << CLR(term::RESET) << "\n";
                std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET) << " Choose IP (number) or type ip:port: ";
                std::string choice;
                if (!readLine(choice)) {
                    ip = ips[0];
                    std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET) << " Non-interactive, using first IP.\n";
                } else {
                    choice = trim(choice);
                    bool isNum = !choice.empty() &&
                                 choice.find_first_not_of("0123456789") == std::string::npos;
                    unsigned long long sel = 0;
                    bool selOk = isNum && parseDigits(choice, sel);
                    if (isNum && choice != "0" &&
                        (!selOk || sel < 1 || sel > (unsigned long long)ips.size())) {
                        std::cout << CLR(term::YELLOW) << "[!] Érvénytelen válasz: " << choice
                                  << CLR(term::RESET) << "\n";
                    }
                    if (selOk && sel >= 1 && sel <= (unsigned long long)ips.size()) {
                        ip = ips[sel - 1];
                    } else if (choice == "0" || choice.empty() || isNum) {
                        std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET) << " Enter server IP (ip:port): ";
                        std::string in;
                        if (!readLine(in) || trim(in).empty()) {
                            std::cerr << CLR(term::RED) << "No server IP provided." << CLR(term::RESET) << "\n"; return 1;
                        }
                        ip = trim(in);
                    } else {
                        ip = choice;
                    }
                }
            }
        }
        if (ip.empty()) { std::cerr << CLR(term::RED) << "No server IP." << CLR(term::RESET) << "\n"; return 1; }
        if (startsWith(ip, "https://")) ip = ip.substr(8);
        else if (startsWith(ip, "http://")) ip = ip.substr(7);
        while (!ip.empty() && ip.back() == '/') ip.pop_back();
        baseUrl = "http://" + ip;
        std::cout << CLR(term::GREEN) << "[+]" << CLR(term::RESET) << " Selected server IP: " << ip << "\n";
        dumper = std::make_unique<FiveMDumper>(baseUrl, token, "", checkpoint);
        if (dumper->getConfiguration()) {
            serverName = dumper->hostname();
            if (serverName.empty() && envName && *envName) serverName = envName;
            bool gotDynamicResponse = false;
            if (serverName.empty()) {
                std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET)
                          << " Szervernev lekerese a /dynamic.json vegpontbol...\n";
                gotDynamicResponse = dumper->fetchDynamicHostname();
                if (gotDynamicResponse) serverName = dumper->hostname();
            }
            std::string cached = getCachedServerName(ip);
            if (serverName.empty() && !cached.empty() && cached != ip) serverName = cached;
            if (serverName.empty() && !testMode && gotDynamicResponse) {
                std::cout << CLR(term::YELLOW) << "[?]" << CLR(term::RESET)
                          << " Adj nevet a szervernek (mappanév, Enter = IP): ";
                std::string in;
                if (readLine(in) && !trim(in).empty()) serverName = trim(in);
            }
            if (serverName.empty()) serverName = ip;
            if (serverName != ip && serverName != "ismeretlen") {
                saveServerName(ip, serverName);
            }
            dumper->setServerName(serverName);
            if (serverName != ip) {
                std::cout << CLR(term::GREEN) << "[+]" << CLR(term::RESET) << " Server Name: "
                          << CLR(term::BOLD) << serverName << CLR(term::RESET) << "\n";
            }
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
    std::cout << "\n" << CLR(term::BOLD) << CLR(term::CYAN) << "--- PHASE 2: Decrypt ---" << CLR(term::RESET) << "\n";
    Decryptor decryptor(dumper->serverDir);
    bool decryptOk = decryptor.runAll();
    std::cout << "\n" << CLR(decryptOk ? term::GREEN : term::YELLOW)
              << "==============================================\n";
    std::cout << (decryptOk ? " Done! Output: " : " Done, but some files failed to decrypt! Output: ")
              << "Servers/" << dumper->serverDir << "/Output\n";
    std::cout << "==============================================" << CLR(term::RESET) << "\n";
    const std::string serverRoot = "Servers/" + dumper->serverDir;
    const bool keepTemp = getenv("DUMPER_KEEP_TEMP") != nullptr;
    if (decryptOk) runReadabilityPass(serverRoot, testMode);
    if (keepTemp) {
        std::cout << CLR(term::YELLOW) << "[!]" << CLR(term::RESET)
                  << " DUMPER_KEEP_TEMP is set, keeping " << serverRoot << "/Temp, "
                  << serverRoot << "/TempCompiled and " << serverRoot << "/Unpacked for inspection.\n";
    } else if (!decryptOk) {
        std::cerr << CLR(term::RED) << "Error: Some files failed to decrypt. Kept " << serverRoot
                  << "/Temp and " << serverRoot << "/Unpacked (encrypted inputs) plus "
                  << serverRoot << "/TempCompiled (compiled scratch files) for diagnosis."
                  << CLR(term::RESET) << "\n";
    } else {
        std::error_code ec;
        fs::remove_all(serverRoot + "/Temp", ec);
        fs::remove_all(serverRoot + "/TempCompiled", ec);
        fs::remove_all(serverRoot + "/Unpacked", ec);
    }
    return 0;
}