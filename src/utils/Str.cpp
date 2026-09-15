#include "Str.h"

#include "../core/Bundler.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#ifdef _WIN32
#include <windows.h>
#endif

namespace fivem {

std::string exeDir() {
#ifdef _WIN32
    char buf[4096];
    DWORD n = GetModuleFileNameA(nullptr, buf, sizeof(buf));
    if (n == 0 || n >= sizeof(buf)) return "";
    std::string full(buf);
    auto slash = full.find_last_of("\\/");
    return slash == std::string::npos ? "" : full.substr(0, slash);
#else
    return "";
#endif
}

std::string resolveTool(const std::string& relative) {
    namespace fsx = std::filesystem;
    std::error_code ec;

    auto norm = [](const std::string& dir) {
        std::string d = dir;
        std::replace(d.begin(), d.end(), '\\', '/');
        while (!d.empty() && d.back() == '/') d.pop_back();
        return d;
    };

    // Candidate roots: cwd, exe dir and three parents above it (project root
    // when running from build/Release: .../Dumper - AllInOne/build/Release).
    std::vector<std::string> roots = { ".", exeDir() };
    std::string up = exeDir();
    for (int i = 0; i < 3; ++i) {
        auto pos = up.find_last_of("\\/");
        if (pos == std::string::npos) break;
        up = up.substr(0, pos);
        roots.push_back(up);
    }

    for (auto& r : roots) {
        if (r.empty()) continue;
        std::string cand = norm(r) + "/" + relative;
        if (fsx::exists(cand, ec)) return cand;
    }

    std::string perr;
    if (fivem::ensurePayload(perr)) {
        std::string cand = norm(payloadRoot()) + "/" + relative;
        if (fsx::exists(cand, ec)) return cand;
    }

    return relative;  // not found: caller's error message shows what was tried
}

std::string safeName(const std::string& name) {
    std::string out = name;
    for (char& c : out) {
        if (c == '<' || c == '>' || c == ':' || c == '"' || c == '/' ||
            c == '\\' || c == '|' || c == '?' || c == '*') {
            c = '_';
        }
    }
    return out;
}

std::string urlQuote(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::ostringstream out;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '/') {
            out << static_cast<char>(c);
        } else {
            out << '%' << hex[(c >> 4) & 0xF] << hex[c & 0xF];
        }
    }
    return out.str();
}

std::string toLower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

bool startsWith(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

bool endsWith(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) return false;
    }
    return true;
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> parts;
    std::string cur;
    std::stringstream ss(s);
    while (std::getline(ss, cur, delim)) parts.push_back(cur);
    return parts;
}

std::vector<std::string> splitStr(const std::string& s, const std::string& delim) {
    std::vector<std::string> parts;
    size_t pos = 0, found;
    while ((found = s.find(delim, pos)) != std::string::npos) {
        parts.push_back(s.substr(pos, found - pos));
        pos = found + delim.size();
    }
    parts.push_back(s.substr(pos));
    return parts;
}

std::string hexEncode(const std::vector<uint8_t>& data) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data) {
        out += digits[b >> 4];
        out += digits[b & 0xF];
    }
    return out;
}

std::vector<uint8_t> hexDecode(const std::string& hex) {
    std::vector<uint8_t> out;
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int hi = val(hex[i]), lo = val(hex[i + 1]);
        if (hi < 0 || lo < 0) break;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::vector<uint8_t> base64Decode(const std::string& in) {
    // Accept standard and URL-safe alphabets
    int val[256];
    std::fill(std::begin(val), std::end(val), -1);
    const std::string alpha =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 64; ++i) val[static_cast<unsigned char>(alpha[i])] = i;
    val[static_cast<unsigned char>('-')] = 62;  // url-safe
    val[static_cast<unsigned char>('_')] = 63;  // url-safe

    std::vector<uint8_t> out;
    uint32_t acc = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        int v = val[static_cast<unsigned char>(c)];
        if (v < 0) continue;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    return out;
}

std::optional<std::vector<uint8_t>> readFileBytes(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return std::nullopt;
    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>());
    return data;
}

static void ensureParent(const std::string& path) {
    std::filesystem::path p(path);
    if (p.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(p.parent_path(), ec);
    }
}

bool writeFileBytes(const std::string& path, const std::vector<uint8_t>& data) {
    try {
        ensureParent(path);
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f.is_open()) return false;
        f.write(reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size()));
        return f.good();
    } catch (...) {
        return false;
    }
}

bool writeTextFile(const std::string& path, const std::string& text) {
    std::vector<uint8_t> data(text.begin(), text.end());
    return writeFileBytes(path, data);
}

uint32_t be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

uint32_t le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

} // namespace fivem
