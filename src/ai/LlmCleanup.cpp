#include "LlmCleanup.h"
#include "Cleanup.h"
#include "LuaLexer.h"
#include "../core/Logger.h"
#include "../crypto/Sha256.h"
#include "../utils/Str.h"
#include "../utils/Term.h"
#include <windows.h>
#include <winhttp.h>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <thread>
#pragma comment(lib, "winhttp.lib")
namespace fs = std::filesystem;
namespace fivem {
namespace {
const LlmModel kCoderModel{
    "coder", "Qwen2.5-Coder-1.5B-Instruct (Q4_K_M)",
    "https://huggingface.co/bartowski/Qwen2.5-Coder-1.5B-Instruct-GGUF/resolve/main/"
    "Qwen2.5-Coder-1.5B-Instruct-Q4_K_M.gguf",
    "f530705d447660a4336c329981af164b471b60b974b1d808d57e8ec9fe23b239", 986048800, false};
const LlmModel kReasoningModel{
    "r1", "DeepSeek-R1-Distill-Qwen-1.5B (Q4_K_M)",
    "https://huggingface.co/bartowski/DeepSeek-R1-Distill-Qwen-1.5B-GGUF/resolve/main/"
    "DeepSeek-R1-Distill-Qwen-1.5B-Q4_K_M.gguf",
    "1741e5b2d062b07acf048bf0d2c514dadf2a48f94e2b4aa0cfe069af3838ee2f", 1117320800, true};
struct EngineAsset {
    const char* asset;
    const char* sha256;
    uint64_t size;
};
constexpr size_t kMaxEngineAssets = 2;
struct EngineBuild {
    const char* backend;
    EngineAsset assets[kMaxEngineAssets];
    size_t assetCount;
    bool needsNvidiaGpu;
    bool needsCudaRuntime;
};
const EngineAsset kCudaBin{
    "llama-b11146-bin-win-cuda-13.4-x64.zip",
    "b1866c0ce76bc7bfb0c24b33e9a37e9669f1be18539b12c74ce361f81c41f047", 149758833};
const EngineAsset kCudaRuntime{
    "cudart-llama-bin-win-cuda-13.4-x64.zip",
    "738f8c251ac22b70c3ae6f83a10cf222725df0395246a2cf58f32bdb85fbe668", 423535356};
const EngineAsset kVulkanBin{
    "llama-b11146-bin-win-vulkan-x64.zip",
    "55a378aa095b466979d85075234f66d7655c7a7483222af0c006c0e55b4d7bd6", 32127004};
const EngineAsset kCpuBin{
    "llama-b11146-bin-win-cpu-x64.zip",
    "14cf1303ca9ac3abd94816850532f9f9a69ac66fbaca3776fc6f9061c2fac1d1", 18560055};
const EngineBuild kCudaSlimBuild{"cuda", {kCudaBin}, 1, true, false};
const EngineBuild kCudaFullBuild{"cuda", {kCudaBin, kCudaRuntime}, 2, true, true};
const EngineBuild kVulkanBuild{"vulkan", {kVulkanBin}, 1, false, false};
const EngineBuild kCpuBuild{"cpu", {kCpuBin}, 1, false, false};
std::string engineUrl(const EngineAsset& a) {
    return "https://github.com/ggml-org/llama.cpp/releases/download/b11146/" +
           std::string(a.asset);
}
std::wstring widen(const std::string& s) {
    if (s.empty()) return L"";
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), w.data(), n);
    return w;
}
std::string narrow(const std::wstring& w) {
    if (w.empty()) return "";
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                      nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), s.data(), n,
                        nullptr, nullptr);
    return s;
}
std::string selectedModelId() {
    const char* want = getenv("DUMPER_LLM_MODEL");
    return want ? want : "coder";
}
std::string modelDir() {
    wchar_t buf[4096];
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, 4096);
    std::wstring root = (n > 0 && n < 4096) ? std::wstring(buf)
                                            : std::wstring(L".") + L"\\FiveMDumper";
    return narrow(root + L"\\FiveMDumper\\models");
}
std::string modelFileName(const LlmModel& m) {
    const std::string url = m.url;
    const size_t slash = url.find_last_of('/');
    return slash == std::string::npos ? "model.gguf" : url.substr(slash + 1);
}
std::string enginePath() {
    return resolveTool("Tools/llama/llama-cli.exe");
}
std::string managedEngineDir() {
    wchar_t buf[4096];
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, 4096);
    std::wstring root = (n > 0 && n < 4096) ? std::wstring(buf) : std::wstring(L".");
    return narrow(root + L"\\FiveMDumper\\engine");
}
bool hasNvidiaGpu() {
    HMODULE nv = LoadLibraryW(L"nvcuda.dll");
    if (!nv) return false;
    FreeLibrary(nv);
    return true;
}
bool cudaRuntimeInstalled() {
    static const char* dirs[] = {
        "C:\\Windows\\System32",
        "C:\\Program Files\\NVIDIA GPU Computing Toolkit\\CUDA\\v13.0\\bin",
        "C:\\Program Files\\NVIDIA GPU Computing Toolkit\\CUDA\\v12.4\\bin",
    };
    for (const char* dir : dirs) {
        std::error_code ec;
        for (const char* ver : {"13", "12", "11", "10"}) {
            if (fs::exists(std::string(dir) + "\\cudart64_" + ver + ".dll", ec)) return true;
        }
    }
    return false;
}
const EngineBuild& pickEngineBuild() {
    const char* want = getenv("DUMPER_LLM_BACKEND");
    const std::string backend = want ? toLower(trim(want)) : "auto";
    const bool runtime = cudaRuntimeInstalled();
    if (backend == "cpu") return kCpuBuild;
    if (backend == "vulkan") return kVulkanBuild;
    if (backend == "cuda") return runtime ? kCudaSlimBuild : kCudaFullBuild;
    if (backend != "auto") return kCpuBuild;
    if (hasNvidiaGpu()) return runtime ? kCudaSlimBuild : kCudaFullBuild;
    std::error_code ec;
    if (fs::exists("C:\\Windows\\System32\\vulkan-1.dll", ec)) return kVulkanBuild;
    return kCpuBuild;
}
std::string findInManaged(const std::string& dir, int depth) {
    if (depth > 4) return "";
    std::error_code ec;
    for (auto& e : fs::directory_iterator(dir, ec)) {
        if (ec) break;
        if (e.is_directory()) {
            const std::string hit = findInManaged(e.path().string(), depth + 1);
            if (!hit.empty()) return hit;
        } else if (toLower(e.path().filename().string()) == "llama-cli.exe") {
            return e.path().string();
        }
    }
    return "";
}
bool hashFile(const std::string& path, std::string& hexOut) {
    return sha256HexFile(path, hexOut);
}
bool downloadToFile(const std::string& url, const std::string& dest, uint64_t expectedSize,
                    const ProgressFn& onProgress, std::string& err) {
    const size_t sep = url.find("://");
    if (sep == std::string::npos) { err = "bad url"; return false; }
    std::string rest = url.substr(sep + 3);
    const size_t slash = rest.find('/');
    const std::string hostPort = rest.substr(0, slash);
    const std::string pathAndQuery = rest.substr(slash);
    const size_t colon = hostPort.find(':');
    const std::wstring host = widen(colon == std::string::npos ? hostPort : hostPort.substr(0, colon));
    const int port = colon == std::string::npos
                         ? (sep == 5 ? 443 : 80)
                         : std::atoi(hostPort.c_str() + colon + 1);
    HINTERNET session = WinHttpOpen(L"FiveMDumper/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { err = "WinHttpOpen failed"; return false; }
    DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(session, WINHTTP_OPTION_REDIRECT_POLICY, &redirect, sizeof(redirect));
    HINTERNET conn = WinHttpConnect(session, host.c_str(), static_cast<INTERNET_PORT>(port), 0);
    if (!conn) { WinHttpCloseHandle(session); err = "connect failed"; return false; }
    HINTERNET req = WinHttpOpenRequest(conn, L"GET", widen(pathAndQuery).c_str(), nullptr,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       (port == 443) ? WINHTTP_FLAG_SECURE : 0);
    if (!req) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        err = "open request failed";
        return false;
    }
    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(req, nullptr)) {
        err = "request failed (" + std::to_string(GetLastError()) + ")";
        WinHttpCloseHandle(req); WinHttpCloseHandle(conn); WinHttpCloseHandle(session);
        return false;
    }
    DWORD status = 0, sz = sizeof(status);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
    if (status != 200) {
        err = "HTTP " + std::to_string(status);
        WinHttpCloseHandle(req); WinHttpCloseHandle(conn); WinHttpCloseHandle(session);
        return false;
    }
    std::error_code ec;
    fs::create_directories(fs::path(dest).parent_path(), ec);
    const std::string tmp = dest + ".part";
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        err = "cannot write " + tmp;
        WinHttpCloseHandle(req); WinHttpCloseHandle(conn); WinHttpCloseHandle(session);
        return false;
    }
    std::vector<char> buf(1 << 16);
    uint64_t done = 0;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(req, &avail)) { err = "read failed"; break; }
        if (avail == 0) break;
        DWORD read = 0;
        if (!WinHttpReadData(req, buf.data(), avail, &read)) { err = "read failed"; break; }
        out.write(buf.data(), static_cast<std::streamsize>(read));
        if (!out) { err = "write failed"; break; }
        done += read;
        if (onProgress) onProgress(done, expectedSize);
    }
    out.close();
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    if (!err.empty()) {
        std::remove(tmp.c_str());
        return false;
    }
    if (expectedSize != 0 && done != expectedSize) {
        std::remove(tmp.c_str());
        err = "size mismatch: got " + std::to_string(done) + ", expected " +
              std::to_string(expectedSize);
        return false;
    }
    std::error_code mv;
    fs::rename(tmp, dest, mv);
    if (mv) {
        err = "cannot move the model into place: " + mv.message();
        return false;
    }
    return true;
}
std::string quoteArg(const std::string& a) {
    const std::wstring w = widen(a);
    if (w.find_first_of(L" \t\"") == std::wstring::npos) return narrow(w);
    std::wstring out = L"\"";
    for (wchar_t c : w) {
        if (c == L'\\') out += L"\\\\";
        else if (c == L'"') out += L"\\\"";
        else out += c;
    }
    out += L'"';
    return narrow(out);
}
struct ProcResult {
    bool started = false;
    bool timedOut = false;
    DWORD exitCode = 1;
    std::string out;
    std::string errText;
};
ProcResult runTool(const std::string& executable, const std::vector<std::string>& args,
                   DWORD timeoutMs) {
    ProcResult r;
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE outRd = nullptr, outWr = nullptr, errRd = nullptr, errWr = nullptr;
    if (!CreatePipe(&outRd, &outWr, &sa, 0) || !CreatePipe(&errRd, &errWr, &sa, 0)) return r;
    SetHandleInformation(outRd, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(errRd, HANDLE_FLAG_INHERIT, 0);
    HANDLE nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (nul == INVALID_HANDLE_VALUE) {
        CloseHandle(outRd); CloseHandle(outWr); CloseHandle(errRd); CloseHandle(errWr);
        return r;
    }
    std::string cmd = quoteArg(executable);
    for (const auto& a : args) cmd += " " + quoteArg(a);
    std::wstring wcmd = widen(cmd);
    std::vector<wchar_t> cmdBuf(wcmd.begin(), wcmd.end());
    cmdBuf.push_back(L'\0');
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nul;
    si.hStdOutput = outWr;
    si.hStdError = errWr;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
        CloseHandle(outRd); CloseHandle(outWr); CloseHandle(errRd); CloseHandle(errWr);
        CloseHandle(nul);
        return r;
    }
    r.started = true;
    CloseHandle(outWr);
    CloseHandle(errWr);
    CloseHandle(nul);
    const size_t kMax = 64u * 1024u * 1024u;
    HANDLE pipes[2] = {outRd, errRd};
    std::string* sinks[2] = {&r.out, &r.errText};
    std::thread drainers[2];
    for (int i = 0; i < 2; ++i) {
        drainers[i] = std::thread([pipes, sinks, kMax, i]() {
            char buf[8192];
            DWORD n = 0;
            while (ReadFile(pipes[i], buf, sizeof(buf), &n, nullptr) && n > 0) {
                if (sinks[i]->size() < kMax) sinks[i]->append(buf, n);
            }
            CloseHandle(pipes[i]);
        });
    }

    if (WaitForSingleObject(pi.hProcess, timeoutMs) == WAIT_TIMEOUT) {
        r.timedOut = true;
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
    } else {
        GetExitCodeProcess(pi.hProcess, &r.exitCode);
    }
    for (auto& t : drainers) t.join();
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return r;
}
void stripReasoning(std::string& text) {
    for (size_t guard = 0; guard < 4; ++guard) {
        size_t open = text.find("<think>");
        size_t openLen = 7;
        if (open == std::string::npos) {
            open = text.find("[Start thinking]");
            openLen = 16;
        }
        if (open == std::string::npos) return;
        size_t close = text.find("</think>", open);
        size_t closeLen = 8;
        if (close == std::string::npos) {
            close = text.find("[End thinking]", open);
            closeLen = 14;
        }
        if (close == std::string::npos) {
            text.clear();
            return;
        }
        text = text.substr(0, open) + text.substr(close + closeLen);
    }
}
std::string extractLua(const std::string& raw, bool& hadFence) {
    std::string text = raw;
    stripReasoning(text);
    hadFence = false;
    std::vector<size_t> marks;
    for (size_t at = text.find("```"); at != std::string::npos;
         at = text.find("```", at + 3)) {
        marks.push_back(at);
    }
    if (marks.size() < 2) return "";
    const size_t open = marks[marks.size() - 2];
    const size_t close = marks[marks.size() - 1];
    const size_t bodyStart = text.find('\n', open);
    if (bodyStart == std::string::npos || close <= bodyStart) return "";
    hadFence = true;
    text = trim(text.substr(bodyStart + 1, close - bodyStart - 1));
    if (text.rfind("--", 0) == 0) {
        const size_t nl = text.find('\n');
        if (nl != std::string::npos) text = trim(text.substr(nl + 1));
    }
    return text;
}
size_t codeTokenCount(const std::string& src) {
    size_t n = 0;
    for (const auto& t : lua::tokenize(src)) {
        if (t.kind == lua::Tok::LineComment || t.kind == lua::Tok::BlockComment) continue;
        if (t.kind == lua::Tok::Space) continue;
        ++n;
    }
    return n;
}
bool equivalentUpToRenaming(const std::string& input, const std::string& output,
                            std::string& why) {
    std::vector<lua::Token> a;
    std::vector<lua::Token> b;
    for (const auto& t : lua::tokenize(input)) {
        if (t.kind == lua::Tok::Space || t.kind == lua::Tok::LineComment ||
            t.kind == lua::Tok::BlockComment) {
            continue;
        }
        a.push_back(t);
    }
    for (const auto& t : lua::tokenize(output)) {
        if (t.kind == lua::Tok::Space || t.kind == lua::Tok::LineComment ||
            t.kind == lua::Tok::BlockComment) {
            continue;
        }
        b.push_back(t);
    }
    if (a.size() != b.size()) {
        why = "csonka vagy toldott: " + std::to_string(a.size()) + " -> " +
              std::to_string(b.size()) + " token";
        return false;
    }
    std::map<std::string, std::string> renamed;
    std::map<std::string, std::string> reverse;
    for (size_t i = 0; i < a.size(); ++i) {
        const lua::Token& x = a[i];
        const lua::Token& y = b[i];
        if (x.kind != y.kind) {
            why = "a " + std::to_string(i) + ". token fajtaja megvaltozott";
            return false;
        }
        if (x.text == y.text) continue;
        if (x.kind != lua::Tok::Name || lua::isKeyword(x.text)) {
            why = "a " + std::to_string(i) + ". token nem azonosithato atnevezéssel: " +
                  x.text + " -> " + y.text;
            return false;
        }
        const auto it = renamed.find(x.text);
        if (it != renamed.end()) {
            if (it->second != y.text) {
                why = "az atnevezés ellentmondásos: " + x.text + " -> " + it->second +
                      " es " + y.text;
                return false;
            }
        } else {
            const auto rev = reverse.find(y.text);
            if (rev != reverse.end()) {
                why = "két azonos nevet kapott: " + rev->second + " es " + x.text;
                return false;
            }
            if (lua::isKeyword(y.text)) {
                why = "a kulcsszó nem lehet uj neven: " + y.text;
                return false;
            }
            renamed.emplace(x.text, y.text);
            reverse.emplace(y.text, x.text);
        }
    }
    return true;
}
bool needsModel(const std::string& src) {
    if (src.find("goto") != std::string::npos) return true;
    for (const auto& t : lua::tokenize(src)) {
        if (t.kind != lua::Tok::Name) continue;
        if (t.text.rfind("SHX", 0) == 0 || t.text.rfind("LCL", 0) == 0 ||
            t.text.rfind("VAR", 0) == 0) {
            return true;
        }
    }
    return false;
}
bool plausibleRewrite(const std::string& input, const std::string& output, bool hadFence,
                      std::string& why) {
    why.clear();
    if (!hadFence) { why = "nincs lezart kodblokk"; return false; }
    if (output.find("```") != std::string::npos) { why = "a blokk belsejeben is van fence"; return false; }
    if (!equivalentUpToRenaming(input, output, why)) return false;
    const auto toks = lua::tokenize(output);
    int depth = 0;
    bool hasCode = false;
    for (const auto& t : toks) {
        if (t.kind == lua::Tok::LineComment || t.kind == lua::Tok::BlockComment) continue;
        if (t.kind == lua::Tok::Space) continue;
        hasCode = true;
        if (t.kind != lua::Tok::Name) continue;
        if (t.text == "function" || t.text == "do" || t.text == "repeat" || t.text == "if") {
            ++depth;
        } else if (t.text == "end" || t.text == "until") {
            if (--depth < 0) { why = "tul sok lezaras"; return false; }
        }
    }
    if (!hasCode) { why = "nincs kod, csak komment"; return false; }
    if (depth != 0) { why = "kiegyenlensetelen blokk, marad " + std::to_string(depth); return false; }
    const size_t before = codeTokenCount(input);
    const size_t after = codeTokenCount(output);
    if (before > 0 && after * 2 < before) {
        why = "csonka: " + std::to_string(before) + " -> " + std::to_string(after) + " token";
        return false;
    }
    return true;
}
}
const std::vector<LlmModel>& llmModels() {
    static const std::vector<LlmModel> models = {kCoderModel, kReasoningModel};
    return models;
}
const LlmModel& llmModelById(const std::string& id) {
    const std::string want = toLower(trim(id));
    for (const auto& m : llmModels()) if (want == m.id) return m;
    return llmModels().front();
}
uint64_t llmEngineDownloadBytes() {
    const EngineBuild& b = pickEngineBuild();
    uint64_t n = 0;
    for (size_t i = 0; i < b.assetCount; ++i) n += b.assets[i].size;
    return n;
}
const char* llmBackendName() { return pickEngineBuild().backend; }
bool llmAvailable(std::string& detail) {
    const std::string engine = findEngine(detail);
    std::error_code ec;
    if (engine.empty()) {
        detail = "a futtatot nem talalhato";
        return false;
    }
    const std::string model = modelDir() + "\\" + modelFileName(llmModelById(selectedModelId()));
    if (!fs::is_regular_file(model, ec)) {
        detail = "engine=" + engine + " (a modell meg nincs letoltve)";
        return false;
    }
    detail = "engine=" + engine + " model=" + model;
    return true;
}
std::string findEngine(std::string& detail) {
    std::error_code ec;
    const std::string manual = enginePath();
    if (fs::is_regular_file(manual, ec)) {
        detail = manual;
        return manual;
    }
    const EngineBuild& build = pickEngineBuild();
    const std::string preferred = findInManaged(managedEngineDir() + "\\" + build.backend, 0);
    if (!preferred.empty()) {
        detail = preferred;
        return preferred;
    }
    const std::string managed = findInManaged(managedEngineDir(), 0);
    if (!managed.empty()) {
        detail = managed;
        return managed;
    }
    detail = "nem talalhato (Tools/llama/llama-cli.exe vagy %LOCALAPPDATA%\\FiveMDumper\\engine)";
    return "";
}
bool ensureEngine(bool interactive, const ProgressFn& onProgress, std::string& enginePathOut,
                  std::string& errOut) {
    errOut.clear();
    const EngineBuild& build = pickEngineBuild();
    std::error_code ec;
    const std::string manual = enginePath();
    if (fs::is_regular_file(manual, ec)) {
        enginePathOut = manual;
        return true;
    }
    const std::string scoped = findInManaged(managedEngineDir() + "\\" + build.backend, 0);
    if (!scoped.empty()) {
        enginePathOut = scoped;
        return true;
    }
    uint64_t totalBytes = 0;
    for (size_t i = 0; i < build.assetCount; ++i) totalBytes += build.assets[i].size;
    const uint64_t mb = totalBytes / (1024 * 1024);
    if (build.needsNvidiaGpu && !hasNvidiaGpu()) {
        errOut = std::string("a ") + build.backend +
                 " build NVIDIA GPU-t igényel, és ezen a gépen nincs";
        return false;
    }
    if (interactive) {
        std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET)
                  << " A llama.cpp futtato nincs telepitve: " << build.backend << " build, " << mb
                  << " MB, " << build.assetCount << " csomag (b11146"
                  << (build.needsCudaRuntime ? ", a CUDA runtime is kulcs" : "") << ").\n"
                  << "    Letoltes es telepites? [y/N]: ";
        std::string answer;
        if (!std::getline(std::cin, answer)) { errOut = "nincs interaktiv bemenet"; return false; }
        answer = toLower(trim(answer));
        if (answer != "y" && answer != "yes" && answer != "i") {
            errOut = "felhasznalo megszakította";
            return false;
        }
    }
    const std::string dir = managedEngineDir() + "\\" + build.backend;
    fs::create_directories(dir, ec);
    const std::string tarExe = "C:\\Windows\\System32\\tar.exe";
    if (!fs::exists(tarExe)) {
        errOut = "a beagyazott Windows unpacker (tar.exe) nem talalhato";
        return false;
    }
    for (size_t i = 0; i < build.assetCount; ++i) {
        const EngineAsset& asset = build.assets[i];
        const std::string zip = dir + "\\" + asset.asset;
        std::string dlErr;
        if (!downloadToFile(engineUrl(asset), zip, asset.size, onProgress, dlErr)) {
            errOut = dlErr;
            return false;
        }
        std::string have;
        if (!hashFile(zip, have) || have != asset.sha256) {
            fs::remove(zip, ec);
            errOut = "a letoltott csomag SHA-256 ellenorzese sikertelen: " +
                     std::string(asset.asset);
            return false;
        }
        const ProcResult r = runTool(tarExe, {"-xf", zip, "-C", dir}, 600000);
        fs::remove(zip, ec);
        if (!r.started || r.exitCode != 0) {
            errOut = "a csomag kicsomagolasa sikertelen: " + std::string(asset.asset);
            return false;
        }
    }
    const std::string found = findInManaged(dir, 0);
    if (found.empty()) {
        errOut = "a kicsomagolt csomagban nincs llama-cli.exe";
        return false;
    }
    enginePathOut = found;
    LOG("llama.cpp telepitve: " + found, LogLevel::INFO);
    return true;
}
bool ensureModel(const LlmOptions& opts, bool interactive, const ProgressFn& onProgress,
                 std::string& modelPath, std::string& errOut) {
    errOut.clear();
    const LlmModel& m = opts.model ? *opts.model : llmModelById(selectedModelId());
    const std::string url = m.url;
    const std::string wantSha = m.sha256;
    const uint64_t wantSize = m.size;
    const std::string dest = modelDir() + "\\" + modelFileName(m);
    modelPath = dest;
    std::error_code ec;
    if (fs::is_regular_file(dest, ec) && fs::file_size(dest, ec) == wantSize) {
        std::string have;
        if (hashFile(dest, have) && have == wantSha) {
            errOut = "mar letoltve";
            return true;
        }
        LOG("a modell hash-e nem egyezik, ujratoltes...", LogLevel::WARNING);
        fs::remove(dest, ec);
    }
    if (interactive) {
        std::cout << CLR(term::CYAN) << "[*]" << CLR(term::RESET)
                  << " A nyelvi modell le kell toltse (" << std::to_string(wantSize / (1024 * 1024))
                  << " MB, DeepSeek-R1-Distill-Qwen-1.5B Q4_K_M).\n"
                  << "    Letoltes? [y/N]: ";
        std::string answer;
        if (!std::getline(std::cin, answer)) { errOut = "nincs interaktiv bemenet"; return false; }
        answer = toLower(trim(answer));
        if (answer != "y" && answer != "yes" && answer != "i") {
            errOut = "felhasznalo megszakította";
            return false;
        }
    }
    LOG("modell letoltes: " + url, LogLevel::INFO);
    std::string dlErr;
    if (!downloadToFile(url, dest, wantSize, onProgress, dlErr)) {
        errOut = dlErr;
        return false;
    }
    std::string have;
    if (!hashFile(dest, have) || have != wantSha) {
        fs::remove(dest, ec);
        errOut = "a letoltott modell SHA-256 ellenorzese sikertelen";
        return false;
    }
    return true;
}
int effectiveMaxTokens(const LlmOptions& opts) {
    if (const char* env = getenv("DUMPER_LLM_MAX_TOKENS")) {
        const int v = std::atoi(env);
        if (v >= 512 && v <= 262144) return v;
    }
    return opts.maxTokens;
}
LlmStats llmRewriteTree(const LlmOptions& opts, const std::string& rootIn,
                        const std::string& rootOut, const std::string& engine,
                        const std::string& model, const ProgressFn& onProgress) {
    LlmStats stats;
    stats.enginePath = engine;
    stats.modelPath = model;
    std::error_code ec;
    std::vector<fs::path> files;
    for (auto& e : fs::recursive_directory_iterator(rootIn, ec)) {
        if (e.is_regular_file() && endsWith(toLower(e.path().extension().string()), ".lua"))
            files.push_back(e.path());
    }
    std::sort(files.begin(), files.end());
    const std::string tempDir = modelDir();
    fs::create_directories(tempDir, ec);
    const std::string sysFile = tempDir + "\\llm-system.txt";
    writeTextFile(sysFile,
                  "You rewrite decompiled Lua 5.4 source for human reading ONLY. "
                  "Your entire reply must be one fenced block that starts with ```lua on "
                  "its own line and ends with ``` on its own line, containing the complete "
                  "rewritten file. Never write an explanation, a list of changes, or any "
                  "text outside the fence.");
    size_t index = 0;
    const ULONGLONG startedAt = GetTickCount64();
    for (const auto& in : files) {
        ++index;
        const fs::path rel = fs::relative(in, rootIn);
        const fs::path out = fs::path(rootOut) / rel;
        auto data = readFileBytes(in.string());
        if (!data) { ++stats.failed; continue; }
        const std::string source(data->begin(), data->end());
        fs::create_directories(out.parent_path(), ec);
        writeFileBytes(out.string(), *data);
        if (source.size() > opts.maxInputBytes) {
            ++stats.skippedTooLarge;
            continue;
        }
        if (!needsModel(source)) {
            ++stats.skippedAlreadyClean;
            continue;
        }

        const ULONGLONG spent = GetTickCount64() - startedAt;
        if (spent >= opts.totalTimeoutMs) {
            ++stats.skippedOutOfTime;
            continue;
        }

        DWORD budget = static_cast<DWORD>(opts.fileTimeoutMs);
        const ULONGLONG left = opts.totalTimeoutMs - spent;
        if (left < budget) budget = static_cast<DWORD>(left);
        if (onProgress) onProgress(index, files.size());
        std::string accepted;
        std::string lastWhy = "ismeretlen";
        for (int attempt = 0; attempt < std::max(1, opts.attempts) && accepted.empty(); ++attempt) {
            std::string task =
                "Rewrite this decompiled Lua 5.4 file for human reading: rename local "
                "variables to meaningful names, fix indentation, drop decompiler commentary, "
                "and turn goto/label blocks into loops where that is safe. Do not change "
                "behaviour.";
            if (attempt > 0) {
                task = "Your previous reply was not accepted. Output nothing but one "
                       "```lua fenced block containing the full rewritten file.";
            }
            const std::string promptFile = tempDir + "\\llm-prompt.txt";
            if (!writeTextFile(promptFile, task + "\n\n```lua\n" + source + "\n```")) {
                lastWhy = "a prompt fajlt nem sikerult kiirni";
                break;
            }
            const ProcResult r =
                runTool(engine, {"-m", model, "-f", promptFile, "-sysf", sysFile, "-st",
                                 "--temp", "0", "-n", std::to_string(effectiveMaxTokens(opts)),
                                 "-c", "16384", "--no-warmup", "--no-escape", "--log-disable",
                                 "--no-display-prompt"},
                        budget);
            if (r.timedOut) {
                lastWhy = "a futtato lejart";
                break;
            }
            if (!r.started || r.exitCode != 0) {
                lastWhy = "a futtato nem fejezte be a futast";
                break;
            }
            bool hadFence = false;
            const std::string lua = extractLua(r.out, hadFence);
            std::string why;
            if (plausibleRewrite(source, lua, hadFence, why)) {
                accepted = lua;
                break;
            }
            lastWhy = why;
        }
        if (accepted.empty()) {
            LOG("a nyelvi modell outputja nem hasznalhato (" + lastWhy +
                    "), a tisztitott fajl marad: " + rel.generic_string(),
                LogLevel::WARNING);
            ++stats.failed;
            continue;
        }
        writeFileBytes(out.string(), std::vector<uint8_t>(accepted.begin(), accepted.end()));
        ++stats.rewritten;
        ++stats.files;
    }
    stats.elapsedMs = static_cast<DWORD>(GetTickCount64() - startedAt);
    return stats;
}
} 