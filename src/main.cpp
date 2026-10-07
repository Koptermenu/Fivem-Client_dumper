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
#include "ai/LlmNaming.h"
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
    std::error_code ec;
    if (!fs::is_directory(outputDir, ec)) return;
    const bool forceCleanup = getenv("DUMPER_CLEANUP") != nullptr;
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
              << cs.inlinedAliases << " beagyazott alias, " << cs.deadStores
              << " halott ertekites torolve, " << cs.collapsedTables
              << " szetbontott tabla visszaallitva, " << cs.bannerRemoved << " banner, "
              << cs.reindentedLines << " sor indentálva)\n";
    if (cs.ambiguousVars > 0) {
        std::cout << CLR(term::YELLOW) << "[!]" << CLR(term::RESET) << " " << cs.ambiguousVars
                  << " valtozonak megmaradt a decompiler neve: a kotesuk egy globalis nevet "
                     "hasznal, amit nem lehet elrejteni.\n";
    }
    if (cs.gotoLabels > 0) {
        std::cout << CLR(term::YELLOW) << "[!]" << CLR(term::RESET) << " " << cs.gotoLabels
                  << " goto/label blokk maradt: ezeket automata atalakitas nelkul nem bantjuk.\n";
    }
    if (cs.ambiguousVars > 0) {
        LOG("atnevezes kimaradt " + std::to_string(cs.ambiguousVars) +
            " valtozonak (nincs egyertelmű kotes vagy a nevet globalis foglalja)", LogLevel::INFO);
    }
}

static void runAiNamingPass(const std::string& serverRoot, bool testMode) {
    const std::string cleanDir = serverRoot + "/Output_clean";
    std::error_code ec;
    if (!fs::is_directory(cleanDir, ec)) return;
    const bool forceAi = getenv("DUMPER_AI_CLEANUP") != nullptr;
    if (!aiNamingAvailable()) {
        if (forceAi) {
            std::cout << CLR(term::YELLOW) << "[!]" << CLR(term::RESET)
                      << " DUMPER_AI_CLEANUP beallitva, de az AI kornyezet (ai/deploy) nem "
                         "talalhato: az AI lepes kihagyva.\n";
        }
        return;
    }
    bool wantAi = forceAi;
    if (!wantAi) {
        if (testMode) return;
        wantAi = askYesNo(
            "\nAI agent betoltese? (egy helyi kis modell megprobalja a megmaradt SHX "
            "regisztereket ertelmes nevekre cserelni a Output_clean fajlokban)",
            false);
    }
    if (!wantAi) return;
    std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET)
              << " AI regiszternevezo indul...\n";
    const NamingStats ns = runAiNaming(cleanDir);
    if (ns.files == 0) {
        std::cout << CLR(term::YELLOW) << "[!]" << CLR(term::RESET)
                  << " Nincs SHX regisztert tartalmazo .lua fajl az Output_clean konyvtarban.\n";
        return;
    }
    std::cout << CLR(ns.renamed > 0 ? term::GREEN : term::YELLOW) << "[+]" << CLR(term::RESET)
              << " AI nevezo kesz: " << ns.files << " fajlba neezve, " << ns.proposed
              << " javaslat, " << ns.accepted << " elfogadva, " << ns.rejected
              << " elutasitva, " << ns.renamed << " regiszter atirva " << ns.filesChanged
              << " fajlban";
    if (ns.luacChecked > 0) {
        std::cout << " (luac: " << ns.luacChecked << " ellenorizve, " << ns.luacReverted
                  << " visszavonva)";
    }
    std::cout << "\n";
    if (ns.rejected > 0) {
        LOG("AI nevezo: " + std::to_string(ns.rejected) + " javaslat elutasitva a "
            "biztonsagi ellenorzesen", LogLevel::INFO);
    }
    if (ns.luacReverted > 0) {
        LOG("AI nevezo: " + std::to_string(ns.luacReverted) + " fajl visszaallitva luac hiba miatt",
            LogLevel::WARNING);
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
    if (const char* aiDir = getenv("DUMPER_AI_DIR")) {
        if (*aiDir) {
            const NamingStats ns = runAiNaming(aiDir);
            std::cout << "AI nevezo: " << ns.files << " fajl, " << ns.proposed << " javaslat, "
                      << ns.accepted << " elfogadott nev, " << ns.rejected << " elutasitva, "
                      << ns.renamed << " atiras, " << ns.luacReverted << " luac-visszavonas\n";
            return 0;
        }
    }
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
        bool configFromCache = false;
        if (!dumper->getConfiguration()) {
            std::string cachedDir;
            if (FiveMDumper::findCachedConfig(baseUrl, cachedDir)) {
                std::cout << CLR(term::YELLOW) << "[!]" << CLR(term::RESET)
                          << " A szerver most nem valaszol (vagy elutasitotta a tokent), de van "
                             "korabbi, cache-elt konfiguracio: " << cachedDir << "\n";
                dumper->setServerName(cachedDir);
                configFromCache = dumper->loadCachedConfiguration();
                if (configFromCache) {
                    std::cout << CLR(term::GREEN) << "[+]" << CLR(term::RESET)
                              << " Cache-elt konfiguracio betoltve. Szerverujrainditas utan a "
                                 "fajlletoltesek lehet, hogy nem mennek: ilyenkor csatlakozz "
                                 "ujra a jatekban, es a checkpoint folytatja.\n";
                }
            }
        }
        if (dumper->configReady()) {
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
    if (!decryptor.grantsLoaded()) {
        std::cout << " Nem sikerult elkezdeni: a kulcstoken hianyzik, ezert egyetlen .fxap "
                     "se nyult hozza.\n    Futtasd meg a letoltest a FiveM-hez csatlakozva, "
                     "hogy a Grants.txt megszulelesre keruljon.\n";
    } else if (decryptOk) {
        std::cout << " Kesz! Output: Servers/" << dumper->serverDir << "/Output\n";
    } else {
        std::cout << " Kesz, de egyes fajlok nem oldodtak fel: Servers/" << dumper->serverDir
                  << "/Output\n";
    }
    std::cout << "==============================================" << CLR(term::RESET) << "\n";
    const std::string serverRoot = "Servers/" + dumper->serverDir;
    const bool keepTemp = getenv("DUMPER_KEEP_TEMP") != nullptr;
    if (decryptOk) {
        runReadabilityPass(serverRoot, testMode);
        runAiNamingPass(serverRoot, testMode);
    }
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