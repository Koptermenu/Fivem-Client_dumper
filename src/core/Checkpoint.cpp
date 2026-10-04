#include "Checkpoint.h"
#include "Logger.h"
#include <windows.h>
#include <cstdio>
#include <fstream>
#include <sstream>
namespace fivem {
namespace {
    std::wstring toWide(const std::string& s) {
        if (s.empty()) return L"";
        int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
        std::wstring w(n, 0);
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), w.data(), n);
        return w;
    }
    bool skipJsonWs(const std::string& json, size_t& pos) {
        while (pos < json.size() &&
               (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r')) {
            ++pos;
        }
        return pos < json.size();
    }
    bool findJsonKey(const std::string& json, const std::string& key, size_t& pos) {
        const std::string needle = "\"" + key + "\"";
        size_t from = 0;
        for (;;) {
            size_t keyPos = json.find(needle, from);
            if (keyPos == std::string::npos) return false;
            from = keyPos + 1;
            size_t p = keyPos + needle.size();
            if (!skipJsonWs(json, p)) return false;
            if (json[p] != ':') continue;
            ++p;
            if (!skipJsonWs(json, p)) return false;
            pos = p;
            return true;
        }
    }
    int hexDigitValue(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }
    bool parseJsonString(const std::string& json, size_t& pos, std::string& out) {
        if (pos >= json.size() || json[pos] != '"') return false;
        ++pos;
        out.clear();
        while (pos < json.size()) {
            char c = json[pos++];
            if (c == '"') return true;
            if (c != '\\') {
                out += c;
                continue;
            }
            if (pos >= json.size()) return false;
            char esc = json[pos++];
            switch (esc) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    if (json.size() - pos < 4u) return false;
                    int byte = 0;
                    for (size_t i = 0; i < 4u; ++i) {
                        int d = hexDigitValue(json[pos + i]);
                        if (d < 0) return false;
                        byte = byte * 16 + d;
                    }
                    pos += 4;
                    out += static_cast<char>(byte & 0xff);
                    break;
                }
                default: out += esc; break;
            }
        }
        return false;
    }
    std::vector<std::string> parseStringArray(const std::string& json, const std::string& key) {
        std::vector<std::string> result;
        size_t pos = 0;
        if (!findJsonKey(json, key, pos)) return result;
        if (json[pos] != '[') return result;
        ++pos;
        for (;;) {
            if (!skipJsonWs(json, pos)) return result;
            if (json[pos] == ']') return result;
            if (json[pos] == ',') {
                ++pos;
                continue;
            }
            if (json[pos] != '"') {
                while (pos < json.size() && json[pos] != ',' && json[pos] != ']') ++pos;
                continue;
            }
            std::string value;
            if (!parseJsonString(json, pos, value)) return result;
            result.push_back(value);
            if (!skipJsonWs(json, pos)) return result;
            if (json[pos] == ',') {
                ++pos;
                continue;
            }
            return result;
        }
    }
    bool extractString(const std::string& json, const std::string& key, std::string& out) {
        size_t pos = 0;
        if (!findJsonKey(json, key, pos)) return false;
        if (json[pos] != '"') return false;
        return parseJsonString(json, pos, out);
    }
    std::string escapeJson(const std::string& s) {
        static const char* hex = "0123456789abcdef";
        std::string out;
        out.reserve(s.size() + 8);
        for (unsigned char c : s) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20) {
                        out += "\\u00";
                        out += hex[c >> 4];
                        out += hex[c & 0x0f];
                    } else {
                        out += static_cast<char>(c);
                    }
                    break;
            }
        }
        return out;
    }
}
bool Checkpoint::load(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    file.close();
    completed_resources = parseStringArray(content, "completed_resources");
    std::string value;
    if (extractString(content, "current_resource", value)) {
        current_resource = value;
    } else {
        current_resource = std::nullopt;
    }
    if (extractString(content, "server_ip", value)) {
        server_ip = value;
    } else {
        server_ip = std::nullopt;
    }
    LOG("Loaded checkpoint from " + filename, LogLevel::INFO);
    return true;
}
bool Checkpoint::save(const std::string& filename) {
    std::ostringstream out;
    out << "{\n";
    out << "  \"completed_resources\": [";
    for (size_t i = 0; i < completed_resources.size(); ++i) {
        if (i > 0) out << ", ";
        out << "\"" << escapeJson(completed_resources[i]) << "\"";
    }
    out << "],\n";
    if (current_resource) {
        out << "  \"current_resource\": \"" << escapeJson(*current_resource) << "\",\n";
    } else {
        out << "  \"current_resource\": null,\n";
    }
    if (server_ip) {
        out << "  \"server_ip\": \"" << escapeJson(*server_ip) << "\"\n";
    } else {
        out << "  \"server_ip\": null\n";
    }
    out << "}\n";
    std::string tmpName = filename + ".tmp";
    {
        std::ofstream file(tmpName, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            LOG("Failed to open checkpoint file for writing: " + tmpName, LogLevel::ERROR);
            return false;
        }
        const std::string data = out.str();
        file.write(data.data(), static_cast<std::streamsize>(data.size()));
        file.flush();
        file.close();
        if (file.fail()) {
            std::remove(tmpName.c_str());
            LOG("Failed to write checkpoint file: " + tmpName, LogLevel::ERROR);
            return false;
        }
    }
    if (!MoveFileExW(toWide(tmpName).c_str(), toWide(filename).c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::remove(tmpName.c_str());
        LOG("Failed to replace checkpoint file: " + filename, LogLevel::ERROR);
        return false;
    }
    LOG("Saved checkpoint to " + filename, LogLevel::INFO);
    return true;
}
void Checkpoint::clear(const std::string& filename) {
    if (std::remove(filename.c_str()) == 0) {
        LOG("Cleared checkpoint file", LogLevel::INFO);
    } else {
        LOG("Failed to remove checkpoint file: " + filename, LogLevel::WARNING);
    }
}
}
