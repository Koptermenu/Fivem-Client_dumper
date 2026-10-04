#include "Json.h"
#include <cctype>
#include <cstdlib>
#include <stdexcept>
namespace fivem {
void Json::skipWs(const std::string& t, size_t& p) {
    while (p < t.size() && (t[p] == ' ' || t[p] == '\t' || t[p] == '\n' || t[p] == '\r'))
        ++p;
}
Json Json::parse(const std::string& text) {
    size_t p = 0;
    skipWs(text, p);
    if (p >= text.size()) throw std::runtime_error("empty json");
    return parseValue(text, p);
}
Json Json::parseValue(const std::string& t, size_t& p) {
    skipWs(t, p);
    if (p >= t.size()) throw std::runtime_error("unexpected end");
    char c = t[p];
    if (c == '{') return parseObject(t, p);
    if (c == '[') return parseArray(t, p);
    if (c == '"') return parseString(t, p);
    if (c == 't' || c == 'f') {
        Json j;
        j.type_ = Type::Bool;
        if (t.compare(p, 4, "true") == 0) { j.bool_ = true; p += 4; }
        else if (t.compare(p, 5, "false") == 0) { j.bool_ = false; p += 5; }
        else throw std::runtime_error("bad bool");
        return j;
    }
    if (c == 'n') {
        if (t.compare(p, 4, "null") == 0) { p += 4; Json j; j.type_ = Type::Null; return j; }
        throw std::runtime_error("bad null");
    }
    return parseNumber(t, p);
}
std::string Json::decodeString(const std::string& raw) {
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i < raw.size(); ++i) {
        char c = raw[i];
        if (c == '\\' && i + 1 < raw.size()) {
            char n = raw[++i];
            switch (n) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    if (i + 4 < raw.size()) {
                        std::string hex = raw.substr(i + 1, 4);
                        unsigned cp = std::strtoul(hex.c_str(), nullptr, 16);
                        i += 4;
                        if (cp < 0x80) {
                            out += static_cast<char>(cp);
                        } else if (cp < 0x800) {
                            out += static_cast<char>(0xC0 | (cp >> 6));
                            out += static_cast<char>(0x80 | (cp & 0x3F));
                        } else {
                            out += static_cast<char>(0xE0 | (cp >> 12));
                            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                            out += static_cast<char>(0x80 | (cp & 0x3F));
                        }
                    }
                    break;
                }
                default: out += n; break;
            }
        } else {
            out += c;
        }
    }
    return out;
}
Json Json::parseString(const std::string& t, size_t& p) {
    ++p;
    std::string raw;
    while (p < t.size()) {
        char c = t[p];
        if (c == '\\') {
            raw += c;
            if (p + 1 < t.size()) { raw += t[p + 1]; p += 2; }
            continue;
        }
        if (c == '"') { ++p; break; }
        raw += c;
        ++p;
    }
    Json j;
    j.type_ = Type::String;
    j.str_ = decodeString(raw);
    return j;
}
Json Json::parseNumber(const std::string& t, size_t& p) {
    size_t start = p;
    if (p < t.size() && (t[p] == '-' || t[p] == '+')) ++p;
    while (p < t.size() &&
           (std::isdigit(static_cast<unsigned char>(t[p])) || t[p] == '.' ||
            t[p] == 'e' || t[p] == 'E' || t[p] == '-' || t[p] == '+'))
        ++p;
    Json j;
    j.type_ = Type::Number;
    j.num_ = std::strtod(t.substr(start, p - start).c_str(), nullptr);
    return j;
}
Json Json::parseArray(const std::string& t, size_t& p) {
    Json j;
    j.type_ = Type::Array;
    ++p;
    skipWs(t, p);
    if (p < t.size() && t[p] == ']') { ++p; return j; }
    while (p < t.size()) {
        j.array_.push_back(parseValue(t, p));
        skipWs(t, p);
        if (p < t.size() && t[p] == ',') { ++p; skipWs(t, p); continue; }
        if (p < t.size() && t[p] == ']') { ++p; break; }
        throw std::runtime_error("bad array");
    }
    return j;
}
Json Json::parseObject(const std::string& t, size_t& p) {
    Json j;
    j.type_ = Type::Object;
    ++p;
    skipWs(t, p);
    if (p < t.size() && t[p] == '}') { ++p; return j; }
    while (p < t.size()) {
        skipWs(t, p);
        if (t[p] != '"') throw std::runtime_error("expected key");
        Json key = parseString(t, p);
        skipWs(t, p);
        if (p >= t.size() || t[p] != ':') throw std::runtime_error("expected colon");
        ++p;
        j.obj_.emplace_back(key.str_, parseValue(t, p));
        skipWs(t, p);
        if (p < t.size() && t[p] == ',') { ++p; continue; }
        if (p < t.size() && t[p] == '}') { ++p; break; }
        throw std::runtime_error("bad object");
    }
    return j;
}
bool Json::has(const std::string& key) const {
    for (auto& kv : obj_) if (kv.first == key) return true;
    return false;
}
const Json& Json::at(const std::string& key) const {
    static Json nullJson;
    for (auto& kv : obj_) if (kv.first == key) return kv.second;
    return nullJson;
}
std::string Json::strAt(const std::string& key, const std::string& def) const {
    const Json& v = at(key);
    if (v.isString()) return v.asString();
    return def;
}
}
