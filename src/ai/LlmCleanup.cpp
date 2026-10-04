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
#include <set>
#include <thread>

#pragma comment(lib, "winhttp.lib")

namespace fs = std::filesystem;

namespace fivem {

namespace {

const char* kDefaultModelUrl =
    "https://huggingface.co/bartowski/DeepSeek-R1-Distill-Qwen-1.5B-GGUF/resolve/main/"
    "DeepSeek-R1-Distill-Qwen-1.5B-Q4_K_M.gguf";
const char* kDefaultModelSha =
    "1741e5b2d062b07acf048bf0d2c514dadf2a48f94e2b4aa0cfe069af3838ee2f";
const uint64_t kDefaultModelSize = 1117320800;

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

std::string modelDir() {
    wchar_t buf[4096];
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, 4096);
    std::wstring root = (n > 0 && n < 4096) ? std::wstring(buf)
                                            : std::wstring(L".") + L"\\FiveMDumper";
    return narrow(root + L"\\FiveMDumper\\models");
}

std::string modelFileName() {
    std::string url = kDefaultModelUrl;
    const size_t slash = url.find_last_of('/');
    return slash == std::string::npos ? "model.gguf" : url.substr(slash + 1);
}

std::string enginePath() {
    return resolveTool("Tools/llama/llama-cli.exe");
}

// SHA-256 of a file, streamed so a 1 GiB model never lands in memory.
bool hashFile(const std::string& path, std::string& hexOut) {
    return sha256HexFile(path, hexOut);
}

// Streaming download: the model must never be buffered in memory.
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
    DWORD exitCode = 1;
    std::string out;
    std::string errText;
};

ProcResult runTool(const std::string& executable, const std::vector<std::string>& args) {
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
    for (auto& t : drainers) t.join();

    WaitForSingleObject(pi.hProcess, 1800000);
    GetExitCodeProcess(pi.hProcess, &r.exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return r;
}

// The model wraps its answer in a fenced block and may emit a reasoning trace.
std::string extractLua(const std::string& raw) {
    std::string text = raw;
    const size_t thinkOpen = text.find("<think>");
    if (thinkOpen != std::string::npos) {
        const size_t thinkClose = text.find("</think>", thinkOpen);
        if (thinkClose != std::string::npos) text = text.substr(thinkClose + 8);
    }
    const size_t fence = text.find("```");
    if (fence != std::string::npos) {
        const size_t bodyStart = text.find('\n', fence);
        if (bodyStart != std::string::npos) {
            const size_t close = text.find("```", bodyStart);
            if (close != std::string::npos) text = text.substr(bodyStart + 1, close - bodyStart - 1);
        }
    }
    text = trim(text);
    if (text.rfind("--", 0) == 0) {
        const size_t nl = text.find('\n');
        if (nl != std::string::npos) text = trim(text.substr(nl + 1));
    }
    return text;
}

bool balancedLua(const std::string& src) {
    int depth = 0;
    for (const auto& t : lua::tokenize(src)) {
        if (t.kind != lua::Tok::Name) continue;
        if (t.text == "function" || t.text == "do" || t.text == "repeat" || t.text == "then") ++depth;
        else if (t.text == "end" || t.text == "until") { if (--depth < 0) return false; }
    }
    return depth == 0;
}

} // namespace

bool llmAvailable(std::string& detail) {
    const std::string engine = enginePath();
    std::error_code ec;
    if (!fs::is_regular_file(engine, ec)) {
        detail = "a futtatot nem talalhato: " + engine +
                 " (helyezd el a llama-cli.exe-t a Tools/llama/ mappaba)";
        return false;
    }
    const std::string model = modelDir() + "\\" + modelFileName();
    if (!fs::is_regular_file(model, ec)) {
        detail = "a modell meg nincs letoltve";
        return false;
    }
    detail = "engine=" + engine + " model=" + model;
    return true;
}

bool ensureModel(const LlmOptions& opts, bool interactive, const ProgressFn& onProgress,
                 std::string& modelPath, std::string& errOut) {
    errOut.clear();
    const std::string url = opts.modelUrl.empty() ? kDefaultModelUrl : opts.modelUrl;
    const std::string wantSha = opts.expectedSha256.empty() ? kDefaultModelSha : opts.expectedSha256;
    const uint64_t wantSize = opts.expectedSize ? opts.expectedSize : kDefaultModelSize;

    const std::string dest = modelDir() + "\\" + modelFileName();
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

    size_t index = 0;
    for (const auto& in : files) {
        ++index;
        const fs::path rel = fs::relative(in, rootIn);
        const fs::path out = fs::path(rootOut) / rel;

        auto data = readFileBytes(in.string());
        if (!data) { ++stats.failed; continue; }
        const std::string source(data->begin(), data->end());
        fs::create_directories(out.parent_path(), ec);
        // Seed the output with the input so a skipped or failed file still lands there.
        writeFileBytes(out.string(), *data);

        if (source.size() > opts.maxInputBytes) {
            ++stats.skippedTooLarge;
            continue;
        }

        if (onProgress) onProgress(index, files.size());

        const std::string promptFile = tempDir + "\\llm-prompt.txt";
        const std::string prompt =
            "You are cleaning up decompiled Lua 5.4 source recovered from a build. "
            "Rewrite it so a human can read it: give local variables meaningful names, fix "
            "indentation, remove decompiler commentary, and convert goto/label blocks into "
            "loops where that is safe. Do not change any behaviour. Reply with the complete "
            "rewritten Lua file inside one ```lua code block and nothing else.\n\n"
            "```lua\n" + source + "\n```\n";
        if (!writeTextFile(promptFile, prompt)) { ++stats.failed; continue; }

        const ProcResult r =
            runTool(engine, {"-m", model, "-f", promptFile, "-no-cnv", "--temp", "0",
                             "-n", std::to_string(opts.maxTokens), "-c", "4096"});
        if (!r.started || r.exitCode != 0) {
            LOG("a nyelvi modell nem futott le a " + rel.generic_string() + " fajlra", LogLevel::WARNING);
            ++stats.failed;
            continue;
        }

        std::string lua = extractLua(r.out);
        if (lua.empty() || !balancedLua(lua)) {
            LOG("a nyelvi modell outputja nem hasznalhato Lua,_keep: " + rel.generic_string(),
                LogLevel::WARNING);
            ++stats.failed;
            continue;
        }

        writeFileBytes(out.string(), std::vector<uint8_t>(lua.begin(), lua.end()));
        ++stats.rewritten;
        ++stats.files;
    }
    return stats;
}

} // namespace fivem