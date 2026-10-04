#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
namespace fivem {
struct LlmModel {
    const char* id;
    const char* displayName;
    const char* url;
    const char* sha256;
    uint64_t size;
    bool reasoning;
};
const std::vector<LlmModel>& llmModels();
const LlmModel& llmModelById(const std::string& id);
struct LlmOptions {
    const LlmModel* model = nullptr;
    size_t maxInputBytes = 16384;
    int maxTokens = 8192;
    int attempts = 2;
    uint32_t fileTimeoutMs = 300000;
    uint32_t totalTimeoutMs = 300000;
};
struct LlmStats {
    int files = 0;
    int rewritten = 0;
    int skippedTooLarge = 0;
    int skippedAlreadyClean = 0;
    int skippedOutOfTime = 0;
    int failed = 0;
    uint32_t elapsedMs = 0;
    std::string enginePath;
    std::string modelPath;
};
using ProgressFn = std::function<void(uint64_t done, uint64_t total)>;
std::string findEngine(std::string& detail);
bool ensureEngine(bool interactive, const ProgressFn& onProgress, std::string& enginePath,
                  std::string& errOut);
bool llmAvailable(std::string& detail);
uint64_t llmEngineDownloadBytes();
const char* llmBackendName();
bool ensureModel(const LlmOptions& opts, bool interactive, const ProgressFn& onProgress,
                 std::string& modelPath, std::string& errOut);
LlmStats llmRewriteTree(const LlmOptions& opts, const std::string& rootIn,
                        const std::string& rootOut, const std::string& enginePath,
                        const std::string& modelPath, const ProgressFn& onProgress);
} 