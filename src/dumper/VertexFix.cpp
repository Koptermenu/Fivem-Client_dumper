#include "dumper/VertexFix.h"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "utils/Str.h"

namespace fsx = std::filesystem;

namespace fivem {
namespace {

const char* kFixerRel = "Bin/vertex-fixer/FivemDecryptFixer.Cli.exe";

// Measured at 0.3 to 0.6 seconds per model file, so 785 models took 242 seconds. The
// tool rewrites in place and a hung child is otherwise indistinguishable from a slow one,
// so the wait is bounded and an overrun is treated as a failure rather than a hang.
const DWORD kChildTimeoutMs = 30 * 60 * 1000;

// Only these three carry vertex buffers this tool knows how to rebuild. Kept separate
// from Decryptor.cpp's STREAM_EXTENSIONS on purpose: that list is not a "files needing
// repair" list, it is a decryption-format classification. Every entry in it is an
// RSC7/RSC8 container, and .awc/.ybn/.ymap/.ymf/.ytd/.ytyp carry no vertex buffers at
// all. Unifying the two lists would either break findFilenameEnd for the non-model RSC
// files or make this scan binaries it cannot repair.
bool isFixable(const std::string& lowerName) {
    return endsWith(lowerName, ".ydr") || endsWith(lowerName, ".ydd") ||
           endsWith(lowerName, ".yft");
}

// Reads one pipe to EOF into its own string.
void drain(HANDLE pipe, std::string& sink) {
    char buf[8192];
    DWORD got = 0;
    while (ReadFile(pipe, buf, sizeof(buf), &got, nullptr) && got > 0)
        sink.append(buf, got);
}

struct ChildResult {
    int exitCode = -1;
    bool timedOut = false;
    bool started = false;
    std::string output;
};

ChildResult runFixer(const std::string& exe, const std::string& workDir) {
    ChildResult res;
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE outRd = nullptr, outWr = nullptr, errRd = nullptr, errWr = nullptr;
    if (!CreatePipe(&outRd, &outWr, &sa, 0)) {
        res.output = "cannot create the stdout pipe";
        return res;
    }
    if (!CreatePipe(&errRd, &errWr, &sa, 0)) {
        CloseHandle(outRd);
        CloseHandle(outWr);
        res.output = "cannot create the stderr pipe";
        return res;
    }
    SetHandleInformation(outRd, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(errRd, HANDLE_FLAG_INHERIT, 0);

    si.hStdOutput = outWr;
    si.hStdError = errWr;
    si.hStdInput = nullptr;
    si.dwFlags |= STARTF_USESTDHANDLES;

    const std::string cmd = "\"" + exe + "\" fix-models \"" + workDir + "\"";
    std::vector<char> buf(cmd.begin(), cmd.end());
    buf.push_back('\0');

    // The tool is .NET and resolves its own dependencies next to its assembly, so the
    // working directory must be the tool's own folder, exactly like the reference driver.
    // path::c_str() is wchar_t on Windows and CreateProcessA wants narrow bytes, so the
    // directory is converted once into a std::string that outlives the call.
    const std::string cwd = fsx::path(exe).parent_path().string();

    PROCESS_INFORMATION pi{};
    // bInheritHandles must be TRUE for the pipes, and the only handles that survive to the
    // child are the two write ends, since the read ends were cleared just above.
    if (!CreateProcessA(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                        nullptr, cwd.empty() ? nullptr : cwd.c_str(), &si, &pi)) {
        CloseHandle(outRd); CloseHandle(outWr); CloseHandle(errRd); CloseHandle(errWr);
        res.output = "cannot start the repair tool";
        return res;
    }
    res.started = true;
    // The parent's copies of the write ends must close or the child never sees EOF.
    CloseHandle(outWr);
    CloseHandle(errWr);

    // Both pipes must be drained at the same time. The tool writes to both, and a real
    // dump produced 345KB of stdout: draining one and then the other would fill the
    // 64KB buffer of the second and deadlock. Two separate sinks, because appending to
    // one shared std::string from two threads is a data race, not a merge.
    std::string errText;
    std::thread a([&] { drain(outRd, res.output); });
    std::thread b([&] { drain(errRd, errText); });

    if (WaitForSingleObject(pi.hProcess, kChildTimeoutMs) == WAIT_TIMEOUT) {
        res.timedOut = true;
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
    }
    a.join();
    b.join();
    CloseHandle(outRd);
    CloseHandle(errRd);
    if (!errText.empty()) {
        res.output += "\n";
        res.output += errText;
    }

    DWORD code = 0;
    if (GetExitCodeProcess(pi.hProcess, &code)) res.exitCode = static_cast<int>(code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return res;
}

// "[MODEL] scanned=N, repaired=N, failed=N". Read it off the end: a long run prints one
// [MODEL n/N] line per file first, and only the trailing line carries all three counters.
bool parseSummary(const std::string& out, VertexFixStats& st) {
    const size_t at = out.rfind("[MODEL] scanned=");
    if (at == std::string::npos) return false;
    const std::string tail = out.substr(at, 200);
    int scanned = 0, repaired = 0, failed = 0;
    if (std::sscanf(tail.c_str(), "[MODEL] scanned=%d, repaired=%d, failed=%d", &scanned,
                    &repaired, &failed) != 3)
        return false;
    st.scanned = scanned;
    st.repaired = repaired;
    st.failed = failed;
    return true;
}

// copy_file opens the destination CREATE_ALWAYS, so an interrupted copy leaves a
// truncated model, which is worse than an unrepaired one. Write to a sibling temporary
// and rename over the original instead, the same way Bundler.cpp stages the payload.
bool replaceFile(const fsx::path& src, const fsx::path& dest) {
    std::error_code ec;
    const uintmax_t bytes = fsx::file_size(src, ec);
    if (ec || bytes == 0) return false;  // an empty result means a truncated write
    std::ifstream in(src, std::ios::binary);
    if (!in) return false;
    fsx::path tmp(dest);
    tmp += L".tmp-" + std::to_wstring(GetCurrentProcessId());
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    char buf[65536];
    while (in) {
        in.read(buf, sizeof(buf));
        const std::streamsize got = in.gcount();
        if (got > 0) out.write(buf, got);
    }
    out.flush();
    const bool wroteOk = out.good();
    out.close();
    if (!wroteOk) {
        fsx::remove(tmp, ec);
        return false;
    }
    // AV and indexers hold new files open for a moment after the writer closes them.
    for (int attempt = 0; attempt < 5; ++attempt) {
        std::error_code renameEc;
        fsx::rename(tmp, dest, renameEc);
        if (!renameEc) return true;
        Sleep(400);
    }
    fsx::remove(tmp, ec);
    return false;
}

}  // namespace

VertexFixStats runVertexFix(const std::string& root) {
    VertexFixStats st;
    std::error_code ec;
    if (root.empty() || !fsx::is_directory(root, ec)) return st;

    const fsx::path base(root);
    std::vector<std::pair<fsx::path, fsx::path>> files;  // original, relative
    // A dedicated error_code per call: sharing one would let a single transient failure
    // end the walk silently and leave a subset of the models unrepaired.
    for (fsx::recursive_directory_iterator it(base, ec), end; it != end; it.increment(ec)) {
        if (ec) {
            st.message = "a modellfajlok bejarasa megszakadt";
            break;
        }
        std::error_code fileEc;
        if (!it->is_regular_file(fileEc) || fileEc) continue;
        const std::string lower = toLower(it->path().string());
        if (!isFixable(lower)) continue;
        std::error_code relEc;
        const fsx::path rel = fsx::relative(it->path(), base, relEc);
        if (relEc || rel.empty()) continue;  // never stage onto the scratch root itself
        files.emplace_back(it->path(), rel);
    }
    if (files.empty()) {
        st.message = "nincs modellfajl";
        return st;
    }
    st.files = static_cast<int>(files.size());

    // The scratch tree sits next to the dump rather than in %TEMP%, so it is always on the
    // same volume as the several hundred megabytes it is about to duplicate.
    fsx::path scratch = base / ("vertexfix-" + std::to_string(GetCurrentProcessId()));
    {
        std::error_code rmEc;
        fsx::remove_all(scratch, rmEc);
    }
    if (!fsx::create_directories(scratch, ec)) {
        st.message = "cannot create the scratch directory";
        return st;
    }

    const auto started = std::chrono::steady_clock::now();
    const std::string exe = resolveTool(kFixerRel);
    if (exe.empty() || !fsx::exists(exe)) {
        std::error_code rmEc;
        fsx::remove_all(scratch, rmEc);
        st.message = "a javito nincs a csomagban (" + std::string(kFixerRel) + ")";
        return st;
    }

    // Keep the relative path. Two resources can both ship "prop.ydr", and flattening would
    // let one overwrite the other in the scratch tree and then be copied back twice.
    for (const auto& f : files) {
        std::error_code dirEc;
        fsx::create_directories((scratch / f.second).parent_path(), dirEc);
        std::error_code copyEc;
        fsx::copy_file(f.first, scratch / f.second, fsx::copy_options::overwrite_existing,
                       copyEc);
    }

    st.ran = true;
    const ChildResult child = runFixer(exe, scratch.string());
    st.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();

    const bool summaryOk = parseSummary(child.output, st);
    if (child.timedOut) {
        st.ok = false;
        st.message = "a javito nem zart be idoben, leallitva";
    } else if (!summaryOk) {
        // Without the counters there is no evidence the run did anything. Treating that
        // as success would report "0 repaired, 0 scanned, 0 errors" for a tool that
        // never ran.
        st.ok = false;
        st.message = "a javito nem adott osszegzest, nem tekinthető sikeresnek";
    } else if (child.exitCode != 0 || st.failed > 0) {
        st.ok = false;
        st.message = "a javito nem tiszta kilepessel lepett (exit " +
                     std::to_string(child.exitCode) + ", failed " +
                     std::to_string(st.failed) + ")";
    } else if (st.scanned != st.files) {
        st.ok = false;
        st.message = "nem minden modellfajlat nezte meg (" + std::to_string(st.scanned) +
                     "/" + std::to_string(st.files) + ")";
    } else {
        st.ok = true;
    }

    // Only copy back on a clean run. The tool rewrites in place, so a run that died
    // partway through leaves a truncated file in the scratch tree, and copying that over
    // a good original would destroy the model for good: there is no second copy once
    // Temp, TempCompiled and Unpacked have been deleted.
    if (st.ok) {
        for (const auto& f : files) {
            if (replaceFile(scratch / f.second, f.first)) st.written++;
        }
        if (st.written == 0 && st.repaired > 0) {
            st.ok = false;
            st.message = "a javito kesz, de egyetlen javított fajl sem kerult vissza";
        }
    }

    std::error_code rmEc;
    fsx::remove_all(scratch, rmEc);
    return st;
}

}  // namespace fivem