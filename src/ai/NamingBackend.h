#pragma once
#include <string>

namespace fivem {

enum class NamingBackend { Local, OpenRouter };

struct NamingQuery {
    NamingBackend backend = NamingBackend::Local;
    bool ready = false;
    std::string detail;
};

NamingQuery resolveNamingBackend();
const char* namingBackendName(NamingBackend backend);

std::string namingQuery(const std::string& prompt, int maxTokens, NamingBackend backend);

bool openRouterConfigured();
std::string openRouterModel();

}  // namespace fivem