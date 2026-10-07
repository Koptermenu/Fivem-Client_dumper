#include "ai/LlmNaming.h"
#include "ai/LuaLexer.h"
#include "core/HttpClient.h"
#include "core/Logger.h"
#include "utils/Json.h"
#include "utils/Str.h"
#include <windows.h>
#include <algorithm>
#include <atomic>
#include <iostream>
#include <filesystem>
#include <map>
#include <mutex>
#include <queue>
#include <regex>
#include <set>
#include <thread>
#include "utils/Term.h"
namespace fs = std::filesystem;

namespace fivem {
namespace {
const char* kServerExe = "ai/deploy/llama-server.exe";
const char* kModelGguf = "ai/deploy/qwen_lua_ck40_q4km.gguf";
const int kPort = 8742;
const size_t kChunkBudget = 6000;
const int kCtxTokens = 12288;
const int kWorkers = 1;
const int kMaxFileBytes = 2 * 1024 * 1024;

const char* kRegisterPattern =
    "SHX[0-9]+_[0-9]+(?:Fn[0-9]+)?|L[0-9]+_[0-9]+|num[0-9]+|text[0-9]+|table[0-9]+";
const std::regex& registerRegex() {
    static const std::regex r(kRegisterPattern);
    return r;
}
const std::regex& identRegex() {
    static const std::regex r("[A-Za-z_][A-Za-z0-9_]*");
    return r;
}

std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

std::vector<lua::Token> lexOrEmpty(const std::string& source) {
    auto tokens = lua::tokenize(source);
    for (const auto& t : tokens) {
        if (!t.closed) return {};
    }
    return tokens;
}

std::string blankNoise(const std::string& source, const std::vector<lua::Token>& tokens) {
    std::string out = source;
    for (const auto& t : tokens) {
        if (t.kind == lua::Tok::String || t.kind == lua::Tok::LineComment ||
            t.kind == lua::Tok::BlockComment) {
            for (size_t i = t.begin; i < t.end && i < out.size(); ++i) {
                if (out[i] != '\n') out[i] = ' ';
            }
        }
    }
    return out;
}

bool isRegisterName(const std::string& s) {
    return std::regex_match(s, registerRegex());
}

std::set<std::string> collectRegisters(const std::string& text) {
    std::set<std::string> regs;
    for (std::sregex_iterator it(text.begin(), text.end(), registerRegex()), end; it != end; ++it) {
        regs.insert(it->str());
    }
    return regs;
}

std::set<std::string> collectIdentifiers(const std::vector<lua::Token>& tokens) {
    std::set<std::string> ids;
    for (const auto& t : tokens) {
        if (t.kind == lua::Tok::Name) ids.insert(t.text);
    }
    return ids;
}

std::set<std::string> declaredLocals(const std::vector<lua::Token>& tokens) {
    std::set<std::string> names;
    for (size_t i = 0; i + 1 < tokens.size(); ++i) {
        if (tokens[i].kind != lua::Tok::Name || tokens[i].text != "local") continue;
        size_t j = i + 1;
        if (j < tokens.size() && tokens[j].kind == lua::Tok::Name &&
            tokens[j].text == "function") {
            ++j;
        }
        while (j < tokens.size() && tokens[j].kind == lua::Tok::Name) {
            names.insert(tokens[j].text);
            ++j;
            if (j < tokens.size() && tokens[j].kind == lua::Tok::Symbol && tokens[j].text == ",") {
                ++j;
            } else {
                break;
            }
        }
        i = j > i ? j - 1 : i;
    }
    return names;
}

std::set<std::string> declaredParams(const std::vector<lua::Token>& tokens) {
    std::set<std::string> names;
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i].kind != lua::Tok::Name || tokens[i].text != "function") continue;
        size_t j = i + 1;
        while (j < tokens.size() &&
               !(tokens[j].kind == lua::Tok::Symbol && tokens[j].text == "(")) {
            ++j;
        }
        if (j >= tokens.size()) break;
        ++j;
        int depth = 1;
        bool expectName = true;
        for (; j < tokens.size() && depth > 0; ++j) {
            const auto& t = tokens[j];
            if (t.kind == lua::Tok::Symbol && t.text == "(") { ++depth; continue; }
            if (t.kind == lua::Tok::Symbol && t.text == ")") { --depth; continue; }
            if (depth == 1 && t.kind == lua::Tok::Name && expectName) {
                names.insert(t.text);
                expectName = false;
            } else if (t.kind == lua::Tok::Symbol && t.text == ",") {
                expectName = true;
            }
        }
        i = j - 1;
    }
    return names;
}

std::vector<size_t> chunkBounds(const std::string& stripped, size_t budget) {
    std::vector<size_t> bounds = {0};
    size_t start = 0;
    size_t depth = 0;
    for (size_t i = 0; i < stripped.size(); ++i) {
        const char c = stripped[i];
        if (c == '{') ++depth;
        else if (c == '}') depth = depth > 0 ? depth - 1 : 0;
        if (c == '\n' && i + 1 > start + budget && depth == 0) {
            bounds.push_back(i + 1);
            start = i + 1;
        }
    }
    if (bounds.back() != stripped.size() && !stripped.empty()) bounds.push_back(stripped.size());
    return bounds;
}

bool classifyProposal(const std::string& key, const std::string& value,
                      const std::set<std::string>& idents, const std::set<std::string>& locals,
                      const std::set<std::string>& params, const std::set<std::string>& taken,
                      std::string* reason = nullptr) {
    auto reject = [&reason](const char* r) {
        if (reason) *reason = r;
        return false;
    };
    if (value.empty() || !std::regex_match(value, identRegex())) return reject("invalid_identifier");
    if (lua::isKeyword(value)) return reject("lua_keyword");
    if (value == key) return reject("self_rename");
    if (!isRegisterName(key)) return reject("not_a_register");
    if (locals.count(value) || params.count(value)) return reject("shadow");
    if (idents.count(value) || taken.count(value)) return reject("collision");
    return true;
}

struct FilePlan {
    std::string relPath;
    std::string code;
    std::vector<lua::Token> tokens;
    std::string stripped;
    std::set<std::string> regs;
    std::set<std::string> idents;
    std::set<std::string> locals;
    std::set<std::string> params;
    std::map<std::string, std::string> accepted;
};

std::map<std::string, std::string> parseMap(const std::string& text) {
    std::map<std::string, std::string> got;
    size_t start = 0;
    while (start < text.size()) {
        size_t end = text.find('\n', start);
        if (end == std::string::npos) end = text.size();
        std::string line = trim(text.substr(start, end - start));
        start = end + 1;
        if (line.empty()) continue;
        const size_t eq = line.find('=');
        if (eq == std::string::npos) break;
        const std::string key = trim(line.substr(0, eq));
        const std::string value = trim(line.substr(eq + 1));
        if (got.count(key)) break;
        if (!key.empty() && !value.empty() && std::regex_match(value, identRegex())) {
            got[key] = value;
        }
    }
    return got;
}

std::string applyRenames(const FilePlan& plan, const std::map<std::string, std::string>& accepted,
                         int& renamedOut) {
    std::vector<uint8_t> mask(plan.code.size(), 0);
    for (const auto& t : plan.tokens) {
        if (t.kind == lua::Tok::String || t.kind == lua::Tok::LineComment ||
            t.kind == lua::Tok::BlockComment) {
            std::fill(mask.begin() + t.begin,
                      mask.begin() + std::min(t.end, plan.code.size()), 1);
        }
    }
    std::vector<uint8_t> protectedMask(plan.code.size(), 0);
    const std::regex fieldRe("[.:][ \\t]*(" + std::string(kRegisterPattern) + ")\\b");
    const std::regex keyRe("[{,][ \\t]*(" + std::string(kRegisterPattern) + ")[ \\t]*=(?!=)");
    for (const std::regex* re : {&fieldRe, &keyRe}) {
        for (std::sregex_iterator it(plan.stripped.begin(), plan.stripped.end(), *re), end;
             it != end; ++it) {
            const size_t pos = static_cast<size_t>(it->position(1));
            const size_t lineStart = plan.stripped.rfind('\n', pos);
            const size_t from = lineStart == std::string::npos ? 0 : lineStart + 1;
            size_t lineEnd = plan.stripped.find('\n', pos);
            if (lineEnd == std::string::npos) lineEnd = plan.stripped.size();
            std::fill(protectedMask.begin() + from, protectedMask.begin() + lineEnd, 1);
        }
    }
    std::string out;
    out.reserve(plan.code.size());
    size_t copied = 0;
    int renamed = 0;
    for (std::sregex_iterator it(plan.code.begin(), plan.code.end(), registerRegex()), end;
         it != end; ++it) {
        const size_t pos = static_cast<size_t>(it->position());
        const size_t len = static_cast<size_t>(it->length());
        const auto found = accepted.find(it->str());
        if (found == accepted.end() || mask[pos] || protectedMask[pos]) continue;
        size_t head = pos;
        while (head > copied && (plan.code[head - 1] == ' ' || plan.code[head - 1] == '\t'))
            --head;
        if (head > copied && (plan.code[head - 1] == '.' || plan.code[head - 1] == ':')) continue;
        out.append(plan.code, copied, pos - copied);
        out += found->second;
        copied = pos + len;
        ++renamed;
    }
    if (renamed == 0) return plan.code;
    out.append(plan.code, copied, plan.code.size() - copied);
    renamedOut = renamed;
    return out;
}

bool luacParses(const std::string& luacPath, const std::string& path) {
    char tmpName[MAX_PATH];
    char tmpDir[MAX_PATH];
    if (!GetTempPathA(sizeof(tmpDir), tmpDir)) return true;
    if (!GetTempFileNameA(tmpDir, "luac", 0, tmpName)) return true;
    const std::string cmd =
        "\"" + luacPath + "\" -p -o \"" + tmpName + "\" \"" + path + "\"";
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    std::vector<char> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back('\0');
    bool parsed = true;
    if (CreateProcessA(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                       nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 30000);
        DWORD code = 0;
        GetExitCodeProcess(pi.hProcess, &code);
        parsed = code == 0;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    DeleteFileA(tmpName);
    return parsed;
}

std::string findLuac() {
    if (const char* env = getenv("DUMPER_LUAC")) {
        if (*env && fs::exists(env)) return env;
    }
    const char* candidates[] = {
        "C:\\Users\\Admin\\AppData\\Local\\Programs\\Lua\\bin\\luac.exe",
        "C:\\Program Files\\Lua\\bin\\luac.exe",
        "C:\\Program Files (x86)\\Lua\\bin\\luac.exe",
    };
    for (const char* c : candidates) {
        if (fs::exists(c)) return c;
    }
    return "";
}

class LlamaServer {
public:
    LlamaServer(const std::string& exe, const std::string& model) {
        const std::string cmd =
            "\"" + exe + "\" -m \"" + model + "\" -c 32768 -np " + std::to_string(kWorkers) +
            " --cont-batching -ngl 99 --port " + std::to_string(kPort) + " -t 8 --no-warmup";
        STARTUPINFOA si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};
        std::vector<char> buf(cmd.begin(), cmd.end());
        buf.push_back('\0');
        started_ = CreateProcessA(nullptr, buf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                                  nullptr, nullptr, &si, &pi) == TRUE;
        if (started_) {
            process_ = pi.hProcess;
            CloseHandle(pi.hThread);
        } else {
            LOG("AI szerver inditasa sikertelen: " + exe, LogLevel::WARNING);
        }
    }
    ~LlamaServer() {
        if (started_) {
            TerminateProcess(process_, 0);
            WaitForSingleObject(process_, 5000);
            CloseHandle(process_);
        }
    }
    LlamaServer(const LlamaServer&) = delete;
    LlamaServer& operator=(const LlamaServer&) = delete;
    bool started() const { return started_; }
    bool waitReady() const {
        HttpClient client;
        for (int i = 0; i < 240; ++i) {
            const HttpResponse r =
                client.get("http://127.0.0.1:" + std::to_string(kPort) + "/health");
            if (r.status == 200) return true;
            if (started() && WaitForSingleObject(process_, 0) != WAIT_TIMEOUT) return false;
            Sleep(500);
        }
        return false;
    }

private:
    HANDLE process_ = nullptr;
    bool started_ = false;
};

struct ChunkJob {
    std::string relPath;
    std::string prompt;
    size_t registers = 0;
};

struct SharedState {
    std::queue<ChunkJob> jobs;
    std::mutex jobsMutex;
    std::map<std::string, std::vector<std::map<std::string, std::string>>> results;
    std::mutex resultsMutex;
    std::atomic<bool> fatal{false};
};

void workerLoop(SharedState& shared) {
    HttpClient client;
    for (;;) {
        ChunkJob job;
        {
            std::lock_guard<std::mutex> lock(shared.jobsMutex);
            if (shared.fatal || shared.jobs.empty()) return;
            job = std::move(shared.jobs.front());
            shared.jobs.pop();
        }
        const int nPredict =
            std::min(1024, 16 + 10 * static_cast<int>(job.registers));
        const std::string body = "{\"prompt\":\"" + jsonEscape(job.prompt) +
                                 "\",\"n_predict\":" + std::to_string(nPredict) +
                                 ",\"temperature\":0,\"cache_prompt\":false,"
                                 "\"stop\":[\"\\n\\n\",\"===\"]}";
        const HttpResponse r =
            client.postJson("http://127.0.0.1:" + std::to_string(kPort) + "/completion", body);
        if (!r.ok()) {
            if (r.status == 0) shared.fatal = true;
            continue;
        }
        const Json j = Json::parse(std::string(r.body.begin(), r.body.end()));
        if (!j.isObject() || !j.has("content")) continue;
        const std::string content = j.strAt("content");
        auto parsed = parseMap(content);
        if (parsed.empty()) continue;
        std::lock_guard<std::mutex> lock(shared.resultsMutex);
        shared.results[job.relPath].push_back(std::move(parsed));
    }
}
}  // namespace

std::string findServerExe() {
    char local[MAX_PATH];
    const DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", local, sizeof(local));
    if (n > 0 && n < sizeof(local)) {
        const std::string cuda =
            std::string(local) + "\\FiveMDumper\\engine\\cuda\\llama-server.exe";
        if (fs::exists(cuda)) return cuda;
    }
    return resolveTool(kServerExe);
}

bool aiNamingAvailable() {
    const std::string exe = findServerExe();
    const std::string model = resolveTool(kModelGguf);
    return !exe.empty() && fs::exists(exe) && !model.empty() && fs::exists(model);
}

NamingStats runAiNaming(const std::string& cleanDir) {
    NamingStats stats;
    const std::string exe = findServerExe();
    const std::string model = resolveTool(kModelGguf);
    if (exe.empty() || !fs::exists(exe) || model.empty() || !fs::exists(model)) return stats;

    std::vector<FilePlan> plans;
    std::error_code ec;
    for (auto& e : fs::recursive_directory_iterator(cleanDir, ec)) {
        if (!e.is_regular_file() || !endsWith(toLower(e.path().extension().string()), ".lua"))
            continue;
        if (e.file_size(ec) > kMaxFileBytes) continue;
        auto data = readFileBytes(e.path().string());
        if (!data) continue;
        FilePlan plan;
        plan.relPath = fs::relative(e.path(), cleanDir).string();
        plan.code.assign(data->begin(), data->end());
        plan.tokens = lexOrEmpty(plan.code);
        if (plan.tokens.empty()) continue;
        plan.stripped = blankNoise(plan.code, plan.tokens);
        plan.regs = collectRegisters(plan.stripped);
        if (plan.regs.empty()) continue;
        plan.idents = collectIdentifiers(plan.tokens);
        plan.locals = declaredLocals(plan.tokens);
        plan.params = declaredParams(plan.tokens);
        plans.push_back(std::move(plan));
    }
    stats.files = static_cast<int>(plans.size());
    if (plans.empty()) return stats;
    std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET) << " " << plans.size()
              << " fajl SHX regiszterekkel. AI szerver inditasa...\n";

    LlamaServer server(exe, model);
    if (!server.started()) {
        std::cout << CLR(term::RED) << "[!]" << CLR(term::RESET)
                  << " Az AI szervert nem sikerult elinditani.\n";
        return stats;
    }
    std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET)
              << " Modell betoltese ( jellemzoen 10-30 masodperc )...\n";
    if (!server.waitReady()) {
        std::cout << CLR(term::RED) << "[!]" << CLR(term::RESET)
                  << " Az AI szerver nem valaszolt idejaban.\n";
        LOG("AI szerver health timeout: " + exe, LogLevel::WARNING);
        return stats;
    }
    std::cout << CLR(term::GREEN) << "[+]" << CLR(term::RESET) << " AI szerver kesz a 127.0.0.1:"
              << kPort << " cimen, " << kWorkers << " parhuzamos munkassal.\n";

    SharedState shared;
    for (const auto& plan : plans) {
        const auto bounds = chunkBounds(plan.stripped, kChunkBudget);
        for (size_t i = 0; i + 1 < bounds.size(); ++i) {
            const std::string chunk = plan.code.substr(bounds[i], bounds[i + 1] - bounds[i]);
            const auto chunkTokens = lexOrEmpty(chunk);
            if (chunkTokens.empty()) continue;
            const std::string strippedChunk = blankNoise(chunk, chunkTokens);
            const std::set<std::string> chunkRegs = collectRegisters(strippedChunk);
            if (chunkRegs.empty()) continue;
        std::string promptChunk = trim(chunk);
        for (size_t pos = promptChunk.find("\r\n"); pos != std::string::npos;
             pos = promptChunk.find("\r\n", pos)) {
            promptChunk.erase(pos, 1);
        }
        shared.jobs.push({plan.relPath, promptChunk + "\n\n=== rename map ===\n",
                          chunkRegs.size()});
        }
    }

    std::vector<std::thread> workers;
    for (int i = 0; i < kWorkers; ++i) {
        workers.emplace_back(workerLoop, std::ref(shared));
    }
    for (auto& w : workers) w.join();

    const std::string luac = findLuac();
    for (auto& plan : plans) {
        auto it = shared.results.find(plan.relPath);
        if (it == shared.results.end()) continue;
        std::set<std::string> taken;
        std::map<std::string, int> reasons;
        for (const auto& proposal : it->second) {
            for (const auto& [key, value] : proposal) {
                ++stats.proposed;
                std::string reason;
                if (plan.regs.count(key) == 0) {
                    reason = "not_a_register";
                } else if (!classifyProposal(key, value, plan.idents, plan.locals, plan.params,
                                             taken, &reason)) {
                    if (reason.empty()) reason = "unknown";
                } else {
                    taken.insert(value);
                    plan.accepted[key] = value;
                    ++stats.accepted;
                    continue;
                }
                ++reasons[reason];
                ++stats.rejected;
            }
        }
        if (!reasons.empty()) {
            std::string summary;
            for (const auto& [r, n] : reasons) {
                summary += r + "=" + std::to_string(n) + " ";
            }
            LOG("AI nevezo " + plan.relPath + ": " + summary, LogLevel::INFO);
        }
        if (plan.accepted.empty()) continue;
        int renamed = 0;
        const std::string rewritten = applyRenames(plan, plan.accepted, renamed);
        if (renamed == 0) continue;
        ++stats.filesChanged;
        stats.renamed += renamed;
        const std::string fullPath = (fs::path(cleanDir) / plan.relPath).string();
        if (!writeFileBytes(fullPath, std::vector<uint8_t>(rewritten.begin(), rewritten.end()))) {
            --stats.filesChanged;
            stats.renamed -= renamed;
            continue;
        }
        if (!luac.empty()) {
            ++stats.luacChecked;
            if (!luacParses(luac, fullPath)) {
                writeFileBytes(fullPath, std::vector<uint8_t>(plan.code.begin(), plan.code.end()));
                ++stats.luacReverted;
                --stats.filesChanged;
                stats.renamed -= renamed;
                LOG("luac visszautasitotta az atnevezett fajlt, visszaallitva: " + plan.relPath,
                    LogLevel::WARNING);
            }
        }
    }
    return stats;
}
}  // namespace fivem
