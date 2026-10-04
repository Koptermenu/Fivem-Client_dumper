#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace fivem {

// Optional readability pass that hands each cleaned .lua file to a local language model.
//
// The model weights are downloaded on request and verified against a pinned SHA-256. The
// inference engine is NOT downloaded: llama.cpp publishes no stable Windows binaries, only
// rolling nightly artifacts, so the executable is expected to be supplied by the user and
// is located with the same resolveTool() lookup that finds Unpacker.exe.
//
// Output never replaces the input: rewritten files go to a separate tree.
struct LlmOptions {
    std::string modelUrl;
    std::string expectedSha256;
    uint64_t expectedSize = 0;
    size_t maxInputBytes = 24576;   // larger files are skipped, not truncated
    int maxTokens = 4096;
};

struct LlmStats {
    int files = 0;
    int rewritten = 0;
    int skippedTooLarge = 0;
    int failed = 0;
    std::string enginePath;
    std::string modelPath;
};

using ProgressFn = std::function<void(uint64_t done, uint64_t total)>;

// Locates llama-cli.exe: first a copy the user placed in Tools/llama/, then the managed
// install under %LOCALAPPDATA%\FiveMDumper\engine. Empty when neither exists.
std::string findEngine(std::string& detail);

// Downloads and unpacks the pinned llama.cpp CPU build, after asking. The tag, asset name,
// size and SHA-256 are all compiled in, so the download is reproducible rather than a
// rolling artifact. Returns false when declined or on failure.
bool ensureEngine(bool interactive, const ProgressFn& onProgress, std::string& enginePath,
                  std::string& errOut);

// True when both the model file and the inference engine are present and usable.
bool llmAvailable(std::string& detail);

// Asks the user, then downloads the model if needed. Returns false when declined or on
// failure; errOut carries the reason either way.
bool ensureModel(const LlmOptions& opts, bool interactive, const ProgressFn& onProgress,
                 std::string& modelPath, std::string& errOut);

// Rewrites every .lua file under rootIn into rootOut using the local model. A file whose
// model output is empty, fenced oddly or not balanced Lua is left as the cleaned input, so
// the tree is never worse than before.
LlmStats llmRewriteTree(const LlmOptions& opts, const std::string& rootIn,
                        const std::string& rootOut, const std::string& enginePath,
                        const std::string& modelPath, const ProgressFn& onProgress);

} // namespace fivem