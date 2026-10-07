#include "ai/NamingBackend.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <vector>

#include <windows.h>

#include "core/HttpClient.h"
#include "utils/Json.h"
#include "utils/Str.h"

namespace fivem {

std::string jsonEscapeForNaming(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

namespace {

const char* kOpenRouterUrl = "https://openrouter.ai/api/v1/chat/completions";
const char* kDefaultModel = "cohere/north-mini-code:free";

std::string envOr(const char* name, const char* fallback) {
    const char* v = getenv(name);
    if (!v) return std::string(fallback);
    const std::string s = trim(v);
    return s.empty() ? std::string(fallback) : s;
}

std::string localQuery(HttpClient& client, const std::string& prompt, int maxTokens) {
    const std::string body = "{\"prompt\":\"" + jsonEscapeForNaming(prompt) +
                             "\",\"n_predict\":" + std::to_string(maxTokens) +
                             ",\"temperature\":0,\"cache_prompt\":false,"
                             "\"stop\":[\"\\n\\n\",\"===\"]}";
    const HttpResponse r =
        client.postJson("http://127.0.0.1:8742/completion", body);
    if (!r.ok()) return std::string();
    const Json j = Json::parse(std::string(r.body.begin(), r.body.end()));
    if (!j.isObject() || !j.has("content")) return std::string();
    return j.strAt("content");
}

std::string apiKey() {
    const char* env = getenv("OPENROUTER_API_KEY");
    if (env && *env) {
        const std::string s = trim(env);
        if (!s.empty()) return s;
    }
    const std::vector<std::string> paths = {
        envOr("OPENROUTER_API_KEY_FILE", ""), "ai/deploy/openrouter.key", "openrouter.key"};
    for (const std::string& p : paths) {
        if (p.empty()) continue;
        std::ifstream in(p, std::ios::binary);
        std::string line;
        while (in && std::getline(in, line)) {
            const std::string s = trim(line);
            if (!s.empty() && s[0] != '#') return s;
        }
    }
    char local[MAX_PATH]{};
    if (GetEnvironmentVariableA("LOCALAPPDATA", local, sizeof(local)) > 0) {
        std::ifstream in(std::string(local) + "\\FiveMDumper\\openrouter.key", std::ios::binary);
        std::string line;
        if (in && std::getline(in, line) && !trim(line).empty()) return trim(line);
    }
    return std::string();
}

}  // namespace

bool openRouterConfigured() { return !apiKey().empty(); }

std::string openRouterModel() { return envOr("OPENROUTER_MODEL", kDefaultModel); }

const char* namingBackendName(NamingBackend backend) {
    return backend == NamingBackend::OpenRouter ? "OpenRouter" : "helyi modell";
}

NamingQuery resolveNamingBackend() {
    NamingQuery q;
    const std::string want = toLower(envOr("DUMPER_AI_BACKEND", "local"));
    if (want == "openrouter" || want == "remote") {
        q.backend = NamingBackend::OpenRouter;
        if (!openRouterConfigured()) {
            q.detail = "OPENROUTER_API_KEY nincs beallitva";
            return q;
        }
        q.ready = true;
        q.detail = openRouterModel();
        return q;
    }
    if (want == "auto") {
        q.backend = openRouterConfigured() ? NamingBackend::OpenRouter : NamingBackend::Local;
    }
    q.ready = true;
    q.detail = q.backend == NamingBackend::OpenRouter ? openRouterModel() : std::string("GGUF");
    return q;
}

std::string namingQuery(const std::string& prompt, int maxTokens, NamingBackend backend) {
    HttpClient client;
    if (backend != NamingBackend::OpenRouter) return localQuery(client, prompt, maxTokens);

    const std::string key = apiKey();
    if (key.empty()) return std::string();
    client.setHeader("Authorization", "Bearer " + key);
    client.setHeader("HTTP-Referer", "https://localhost/fivem-dumper");

    const std::string body =
        "{\"model\":\"" + jsonEscapeForNaming(openRouterModel()) + "\",\"temperature\":0," +
        "\"max_tokens\":" + std::to_string(std::min(4096, std::max(16, maxTokens))) +
        ",\"messages\":[{\"role\":\"user\",\"content\":\"" + jsonEscapeForNaming(prompt) + "\"}]}";
    const HttpResponse r = client.postJson(kOpenRouterUrl, body);
    if (!r.ok()) return std::string();
    const Json j = Json::parse(std::string(r.body.begin(), r.body.end()));
    if (!j.isObject()) return std::string();
    const Json& choices = j.at("choices");
    if (!choices.isArray() || choices.arr().empty()) return std::string();
    const Json& msg = choices.arr().front().at("message");
    if (!msg.isObject() || !msg.has("content")) return std::string();
    return msg.strAt("content");
}

}  // namespace fivem