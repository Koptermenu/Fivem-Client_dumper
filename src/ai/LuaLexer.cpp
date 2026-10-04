#include "LuaLexer.h"
#include <cctype>
#include <set>
namespace fivem::lua {
namespace {
const std::set<std::string>& keywords() {
    static const std::set<std::string> kw = {
        "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "goto",
        "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "until",
        "while",
    };
    return kw;
}
int longBracketLevel(const std::string& s, size_t pos) {
    if (pos >= s.size() || s[pos] != '[') return -1;
    size_t i = pos + 1;
    int level = 0;
    while (i < s.size() && s[i] == '=') { ++level; ++i; }
    if (i >= s.size() || s[i] != '[') return -1;
    return level;
}
size_t longBracketBodyEnd(const std::string& s, size_t bodyStart, int level) {
    const std::string close = "]" + std::string(level, '=') + "]";
    const size_t at = s.find(close, bodyStart);
    return at == std::string::npos ? std::string::npos : at + close.size();
}
bool hasNewline(const std::string& s, size_t begin, size_t end) {
    return s.find('\n', begin) < end;
}
}
bool isIdentifierStart(char c) {
    return std::isalpha(static_cast<unsigned char>(c)) != 0 || c == '_';
}
bool isIdentifierChar(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
}
bool isKeyword(const std::string& name) { return keywords().count(name) != 0; }
bool isOpeningKeyword(const std::string& name) {
    return name == "then" || name == "do" || name == "repeat" || name == "function";
}
bool isClosingKeyword(const std::string& name) {
    return name == "end" || name == "until" || name == "else" || name == "elseif";
}
std::vector<Token> tokenize(const std::string& s) {
    std::vector<Token> tokens;
    size_t i = 0;
    const size_t n = s.size();
    while (i < n) {
        const char c = s[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            const size_t start = i;
            while (i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) ++i;
            tokens.push_back({Tok::Space, start, i, s.substr(start, i - start), false});
            continue;
        }
        if (c == '-' && i + 1 < n && s[i + 1] == '-') {
            const size_t start = i;
            const size_t afterDashes = i + 2;
            const int level = longBracketLevel(s, afterDashes);
            if (level >= 0) {
                const size_t bodyEnd = longBracketBodyEnd(s, afterDashes + level + 2, level);
                const bool closed = bodyEnd != std::string::npos;
                const size_t close = closed ? bodyEnd : n;
                tokens.push_back({Tok::BlockComment, start, close,
                                  s.substr(afterDashes + level + 2,
                                           close - (afterDashes + level + 2)),
                                  hasNewline(s, start, close), closed});
                i = close;
            } else {
                size_t eol = s.find('\n', afterDashes);
                if (eol == std::string::npos) eol = n;
                if (eol > afterDashes && s[eol - 1] == '\r') --eol;
                tokens.push_back({Tok::LineComment, start, eol, s.substr(afterDashes, eol - afterDashes), false});
                i = eol;
            }
            continue;
        }
        if (c == '[') {
            const int level = longBracketLevel(s, i);
            if (level >= 0) {
                const size_t bodyStart = i + level + 2;
                const size_t bodyEnd = longBracketBodyEnd(s, bodyStart, level);
                const bool closed = bodyEnd != std::string::npos;
                const size_t close = closed ? bodyEnd : n;
                tokens.push_back({Tok::String, i, close, s.substr(bodyStart, close - bodyStart),
                                  hasNewline(s, i, close), closed});
                i = close;
                continue;
            }
        }
        if (c == '\'' || c == '"') {
            const size_t start = i;
            const char quote = c;
            ++i;
            std::string body;
            bool closed = false;
            while (i < n) {
                if (s[i] == '\\' && i + 1 < n) { body += s[i]; body += s[i + 1]; i += 2; continue; }
                if (s[i] == quote) { ++i; closed = true; break; }
                body += s[i++];
            }
            tokens.push_back({Tok::String, start, i, body, hasNewline(s, start, i), closed});
            continue;
        }
        if (std::isdigit(static_cast<unsigned char>(c)) ||
            (c == '.' && i + 1 < n && std::isdigit(static_cast<unsigned char>(s[i + 1])))) {
            const size_t start = i;
            while (i < n && (std::isalnum(static_cast<unsigned char>(s[i])) || s[i] == '.' ||
                             s[i] == '+' || s[i] == '-' ||
                             ((s[i] == '+' || s[i] == '-') && i > start &&
                              !(s[i - 1] == 'e' || s[i - 1] == 'E' || s[i - 1] == 'p' ||
                                s[i - 1] == 'P')))) {
                ++i;
            }
            tokens.push_back({Tok::Number, start, i, s.substr(start, i - start), false});
            continue;
        }
        if (isIdentifierStart(c)) {
            const size_t start = i;
            while (i < n && isIdentifierChar(s[i])) ++i;
            tokens.push_back({Tok::Name, start, i, s.substr(start, i - start), false});
            continue;
        }
        tokens.push_back({Tok::Symbol, i, i + 1, std::string(1, c), false});
        ++i;
    }
    tokens.push_back({Tok::End, n, n, {}, false});
    return tokens;
}
} 