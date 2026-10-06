#include "Cleanup.h"
#include "LuaLexer.h"
#include "../core/Logger.h"
#include "../utils/Str.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <set>
namespace fs = std::filesystem;
namespace fivem {
namespace {
using lua::Tok;
using lua::Token;
bool isSyntheticName(const std::string& name, std::string& suffix) {
    static const char* typeStems[] = {"text", "num"};
    for (const char* stemText : typeStems) {
        const std::string stem = stemText;
        if (name.rfind(stem, 0) != 0 || name.size() == stem.size()) continue;
        bool allDigits = true;
        for (size_t k = stem.size(); k < name.size(); ++k)
            if (!std::isdigit(static_cast<unsigned char>(name[k]))) allDigits = false;
        if (!allDigits) continue;
        suffix.clear();
        return true;
    }
    size_t i = 0;
    if (name.rfind("SHX", 0) == 0) i = 3;
    else if (name[0] == 'L') i = 1;
    else return false;
    if (i >= name.size() || !std::isdigit(static_cast<unsigned char>(name[i]))) return false;
    while (i < name.size() && std::isdigit(static_cast<unsigned char>(name[i]))) ++i;
    if (i >= name.size() || name[i] != '_') return false;
    ++i;
    if (i >= name.size() || !std::isdigit(static_cast<unsigned char>(name[i]))) return false;
    const size_t suffixStart = i;
    while (i < name.size() && std::isdigit(static_cast<unsigned char>(name[i]))) ++i;
    if (i != name.size()) return false;
    suffix = name.substr(suffixStart);
    return true;
}
std::string sanitizeIdentifier(const std::string& raw) {
    std::string out;
    for (char c : raw) {
        if (lua::isIdentifierChar(c)) out += c;
        else if (!out.empty() && out.back() != '_') out += '_';
    }
    while (!out.empty() && out.front() == '_') out.erase(out.begin());
    while (!out.empty() && out.back() == '_') out.pop_back();
    if (out.empty() || lua::isKeyword(out) ||
        std::isdigit(static_cast<unsigned char>(out[0]))) {
        return "";
    }
    return out;
}
size_t significantIndex(const std::vector<Token>& toks, size_t from) {
    const size_t n = toks.size();
    size_t k = from;
    while (k < n && (toks[k].kind == Tok::Space || toks[k].kind == Tok::LineComment ||
                     toks[k].kind == Tok::BlockComment)) {
        ++k;
    }
    return k;
}
std::string tableNameField(const std::vector<Token>& toks, size_t open) {
    const size_t n = toks.size();
    for (size_t i = open + 1; i < n; ++i) {
        if (toks[i].kind == Tok::Symbol && (toks[i].text == "}" || toks[i].text == "{"))
            return "";
        if (toks[i].kind != Tok::Name || toks[i].text != "name") continue;
        const size_t eq = significantIndex(toks, i + 1);
        if (eq >= n || toks[eq].kind != Tok::Symbol || toks[eq].text != "=") continue;
        const size_t val = significantIndex(toks, eq + 1);
        if (val >= n || toks[val].kind != Tok::String) continue;
        std::string raw = toks[val].text;
        if (!raw.empty() && (raw.front() == '"' || raw.front() == '\'')) raw.erase(raw.begin());
        if (!raw.empty() && (raw.back() == '"' || raw.back() == '\'')) raw.pop_back();
        const std::string id = sanitizeIdentifier(raw);
        return id;
    }
    return "";
}
std::string nameFromBinding(const std::vector<Token>& toks, size_t nameIdx) {
    const size_t n = toks.size();
    const size_t assign = significantIndex(toks, nameIdx + 1);
    if (assign >= n || toks[assign].kind != Tok::Symbol || toks[assign].text != "=") return "";
    {
        size_t eq = nameIdx;
        while (eq > 0 && toks[eq - 1].kind == Tok::Space) --eq;
        if (eq > 0 && toks[eq - 1].kind == Tok::Symbol && toks[eq - 1].text == "=") {
            size_t f = eq - 1;
            while (f > 0 && toks[f - 1].kind == Tok::Space) --f;
            if (f > 0 && toks[f - 1].kind == Tok::Name &&
                !lua::isKeyword(toks[f - 1].text)) {
                size_t d = f - 1;
                while (d > 0 && toks[d - 1].kind == Tok::Space) --d;
                if (d > 0 && toks[d - 1].kind == Tok::Symbol && toks[d - 1].text == ".") {
                    const std::string field = sanitizeIdentifier(toks[f - 1].text);
                    if (!field.empty()) return field;
                }
            }
        }
    }
    const size_t i = significantIndex(toks, assign + 1);
    if (i >= n) return "";
    if (toks[i].kind == Tok::Name && toks[i].text == "function") return "callback";
    if (toks[i].kind == Tok::Symbol && toks[i].text == "{") {
        const std::string named = tableNameField(toks, i);
        if (!named.empty()) return named;
        return "table";
    }
    if (toks[i].kind == Tok::Name && (toks[i].text == "true" || toks[i].text == "false"))
        return "flag";
    if (toks[i].kind == Tok::Number) return "num";
    if (toks[i].kind == Tok::String) return "text";
    if (toks[i].kind != Tok::Name || lua::isKeyword(toks[i].text)) return "";
    std::string candidate = toks[i].text;
    size_t after = i + 1;
    for (;;) {
        const size_t dot = significantIndex(toks, after);
        if (dot + 1 < n && toks[dot].kind == Tok::Symbol && toks[dot].text == "." &&
            toks[dot + 1].kind == Tok::Name && !lua::isKeyword(toks[dot + 1].text)) {
            candidate = toks[dot + 1].text;
            after = dot + 2;
            continue;
        }
        break;
    }
    const size_t call = significantIndex(toks, after);
    const bool isCall = call < n && toks[call].kind == Tok::Symbol &&
                        (toks[call].text == "(" || toks[call].text == ":");
    const std::string base = sanitizeIdentifier(candidate);
    if (base.empty()) return "";
    return isCall ? base + "Fn" : base;
}
struct InlineEdit {
    std::set<size_t> drop;
    std::map<size_t, std::string> replace;
};
bool statementEndsHere(const std::string& src, const std::vector<Token>& toks, size_t idx) {
    const size_t next = significantIndex(toks, idx + 1);
    if (next >= toks.size()) return true;
    if (toks[next].kind == Tok::Symbol && toks[next].text == ";") return true;
    return src.find('\n', toks[idx].end) < toks[next].begin;
}
size_t statementEnd(const std::vector<Token>& toks, size_t start, size_t last) {
    for (size_t i = last + 1; i < toks.size(); ++i) {
        if (toks[i].kind == Tok::End) return last;
        if (toks[i].kind == Tok::Symbol && toks[i].text == ";") return i;
        if (toks[i].kind == Tok::Space) {
            if (toks[i].text.find('\n') != std::string::npos) return i;
            continue;
        }
        return last;
    }
    (void)start;
    return last;
}
bool planInlineAlias(const std::string& src, const std::vector<Token>& toks,
                     const std::string& name, InlineEdit& edit) {
    const size_t n = toks.size();
    size_t declLocal = n;
    for (size_t i = 0; i < n; ++i) {
        if (toks[i].kind != Tok::Name || toks[i].text != "local") continue;
        size_t k = significantIndex(toks, i + 1);
        if (k < n && toks[k].kind == Tok::Name && toks[k].text == "function") continue;
        for (;;) {
            if (k >= n || toks[k].kind != Tok::Name) break;
            const size_t after = significantIndex(toks, k + 1);
            if (after < n && toks[after].kind == Tok::Symbol && toks[after].text == "=") break;
            if (toks[k].text == name) {
                declLocal = i;
                break;
            }
            if (after < n && toks[after].kind == Tok::Symbol && toks[after].text == ",") {
                k = significantIndex(toks, after + 1);
                continue;
            }
            break;
        }
        if (declLocal != n) break;
    }
    if (declLocal == n) return false;
    size_t assign = n, value = n;
    for (size_t i = 0; i < n; ++i) {
        if (toks[i].kind != Tok::Name || toks[i].text != name) continue;
        const size_t eq = significantIndex(toks, i + 1);
        if (eq >= n || toks[eq].kind != Tok::Symbol || toks[eq].text != "=") continue;
        if (assign != n) return false;
        assign = i;
        value = significantIndex(toks, eq + 1);
    }
    if (assign == n || value >= n) return false;
    const Token& v = toks[value];
    const bool isLiteral = v.kind == Tok::String || v.kind == Tok::Number ||
                           (v.kind == Tok::Name && (v.text == "true" || v.text == "false"));
    const bool isGlobalName = v.kind == Tok::Name && !lua::isKeyword(v.text);
    if (!isLiteral && !isGlobalName) return false;
    if (!statementEndsHere(src, toks, value)) return false;
    size_t declName = n;
    {
        size_t k = significantIndex(toks, declLocal + 1);
        while (k < n && toks[k].kind == Tok::Name) {
            if (toks[k].text == name) {
                declName = k;
                break;
            }
            const size_t after = significantIndex(toks, k + 1);
            if (after < n && toks[after].kind == Tok::Symbol && toks[after].text == ",") {
                k = significantIndex(toks, after + 1);
                continue;
            }
            break;
        }
    }
    if (declName == n) return false;
    size_t use = n;
    for (size_t i = 0; i < n; ++i) {
        if (toks[i].kind != Tok::Name || toks[i].text != name) continue;
        if (i == assign || i == declName) continue;
        if (use != n) return false;
        use = i;
    }
    if (use == n || use < assign) return false;
    for (size_t i = 0; i < assign; ++i) {
        if (i == declName || i == declLocal) continue;
        if (toks[i].kind != Tok::Name || toks[i].text != name) continue;
        return false;
    }
    const std::string valueText = src.substr(v.begin, v.end - v.begin);
    const size_t afterUse = significantIndex(toks, use + 1);
    if (afterUse < n && toks[afterUse].kind == Tok::Symbol && toks[afterUse].text == ":") {
        if (!isGlobalName) return false;
    }
    size_t declLast = declName;
    bool otherNames = false;
    {
        size_t k = significantIndex(toks, declLocal + 1);
        while (k < n && toks[k].kind == Tok::Name) {
            declLast = k;
            if (k != declName) otherNames = true;
            const size_t after = significantIndex(toks, k + 1);
            if (after < n && toks[after].kind == Tok::Symbol && toks[after].text == ",") {
                k = significantIndex(toks, after + 1);
                continue;
            }
            break;
        }
    }
    const size_t declEnd = statementEnd(toks, declLocal, declLast);
    const size_t assignEnd = statementEnd(toks, assign, value);
    if (!otherNames) {
        for (size_t i = declLocal; i <= declEnd; ++i) edit.drop.insert(i);
    } else {
        edit.drop.insert(declName);
        const size_t after = significantIndex(toks, declName + 1);
        if (after < n && after <= declLast && toks[after].kind == Tok::Symbol &&
            toks[after].text == ",") {
            edit.drop.insert(after);
            if (after + 1 < n && toks[after + 1].kind == Tok::Space) edit.drop.insert(after + 1);
        } else if (declName > declLocal) {
            for (size_t k = declName; k > declLocal; --k) {
                if (toks[k].kind != Tok::Symbol || toks[k].text != ",") continue;
                edit.drop.insert(k);
                if (k > 0 && toks[k - 1].kind == Tok::Space) edit.drop.insert(k - 1);
                break;
            }
        }
    }
    for (size_t i = assign; i <= assignEnd; ++i) edit.drop.insert(i);
    edit.replace[use] = valueText;
    return true;
}
std::string applyInline(const std::string& src, const std::vector<Token>& toks,
                        const InlineEdit& edit) {
    std::string out;
    out.reserve(src.size());
    for (size_t i = 0; i < toks.size(); ++i) {
        if (toks[i].kind == Tok::End) break;
        if (edit.drop.count(i)) continue;
        if (auto it = edit.replace.find(i); it != edit.replace.end()) {
            out += it->second;
            continue;
        }
        out.append(src, toks[i].begin, toks[i].end - toks[i].begin);
    }
    std::string collapsed;
    collapsed.reserve(out.size());
    size_t i = 0;
    while (i < out.size()) {
        if (out[i] == '\n' || out[i] == '\r') {
            while (i < out.size() && (out[i] == '\n' || out[i] == '\r' || out[i] == ' ' ||
                                      out[i] == '\t')) {
                ++i;
            }
            collapsed += '\n';
            continue;
        }
        collapsed += out[i];
        ++i;
    }
    return collapsed;
}
std::set<std::string> collectLocalNames(const std::vector<Token>& toks);
constexpr size_t kNone = static_cast<size_t>(-1);
bool isSideEffectFreeValue(const Token& v) {
    if (v.kind == Tok::String || v.kind == Tok::Number) return true;
    if (v.kind != Tok::Name) return false;
    if (v.text == "nil" || v.text == "true" || v.text == "false") return true;
    return !lua::isKeyword(v.text);
}
struct NameUses {
    std::vector<size_t> writes;
    std::vector<size_t> reads;
    size_t declLocal = kNone;
    size_t declName = kNone;
    size_t declLast = kNone;
    bool declShared = false;
    bool ambiguous = false;
};
std::map<std::string, NameUses> indexNames(const std::vector<Token>& toks,
                                          std::map<size_t, std::vector<size_t>>& declLists) {
    const size_t n = toks.size();
    std::map<std::string, NameUses> index;
    std::vector<char> isDeclName(n, 0);
    for (size_t i = 0; i < n; ++i) {
        if (toks[i].kind != Tok::Name || toks[i].text != "local") continue;
        size_t k = significantIndex(toks, i + 1);
        if (k < n && toks[k].kind == Tok::Name && toks[k].text == "function") continue;
        std::vector<size_t> names;
        while (k < n && toks[k].kind == Tok::Name && !lua::isKeyword(toks[k].text)) {
            names.push_back(k);
            const size_t after = significantIndex(toks, k + 1);
            if (after < n && toks[after].kind == Tok::Symbol && toks[after].text == ",") {
                k = significantIndex(toks, after + 1);
                continue;
            }
            break;
        }
        for (size_t p : names) {
            NameUses& u = index[toks[p].text];
            if (u.declName == kNone) {
                u.declLocal = i;
                u.declName = p;
            }
        }
        if (!names.empty()) {
            const size_t last = names.back();
            for (size_t p : names) {
                NameUses& u = index[toks[p].text];
                u.declLast = last;
                u.declShared = names.size() > 1;
                isDeclName[p] = 1;
            }
            declLists[i] = names;
        }
    }
    for (size_t i = 0; i < n; ++i) {
        if (toks[i].kind != Tok::Name || isDeclName[i]) continue;
        const std::string& name = toks[i].text;
        NameUses& u = index[name];
        const size_t next = significantIndex(toks, i + 1);
        if (next >= n) {
            u.reads.push_back(i);
            continue;
        }
        if (toks[next].kind == Tok::Symbol) {
            if (toks[next].text == "=") {
                u.writes.push_back(i);
                continue;
            }
            if (toks[next].text == ",") {
                const size_t after = significantIndex(toks, next + 1);
                if (after < n && toks[after].kind == Tok::Name &&
                    !lua::isKeyword(toks[after].text) && !isDeclName[after]) {
                    u.ambiguous = true;
                    index[toks[after].text].ambiguous = true;
                }
            }
        }
        u.reads.push_back(i);
    }
    for (size_t i = 0; i + 1 < n; ++i) {
        if (toks[i].kind != Tok::Name || toks[i].text != "for") continue;
        for (size_t k = i + 1; k < n && k < i + 6; ++k) {
            if (toks[k].kind == Tok::Name && toks[k].text == "do") break;
            if (toks[k].kind == Tok::Name && toks[k].text != "in" &&
                !lua::isKeyword(toks[k].text)) {
                index[toks[k].text].ambiguous = true;
            }
        }
    }
    return index;
}
std::vector<int> functionDepths(const std::vector<Token>& toks) {
    const size_t n = toks.size();
    std::vector<int> depth(n, 0);
    int d = 0;
    int functions = 0;
    std::string previous;
    for (size_t i = 0; i < n; ++i) {
        depth[i] = functions;
        if (toks[i].kind != Tok::Name) continue;
        const std::string& w = toks[i].text;
        if (w == "function" || w == "if" || w == "for" || w == "while") {
            ++d;
            if (w == "function") ++functions;
        } else if (w == "do") {
            if (previous != "for" && previous != "while") ++d;
        } else if (w == "end") {
            if (d > 0) --d;
            if (functions > 0) --functions;
        } else if (w == "until") {
            if (d > 0) --d;
        }
        if (w != "then" && w != "do" && w != "else" && w != "elseif" && w != "repeat" &&
            w != "end" && w != "until")
            previous = w;
        else if (w == "end" || w == "until" || w == "else" || w == "elseif")
            previous.clear();
    }
    return depth;
}
std::string rebuildCollapsed(const std::string& src, const std::vector<Token>& toks,
                             const std::set<size_t>& drop,
                             const std::map<size_t, std::string>& replace) {
    std::string out;
    out.reserve(src.size());
    for (size_t i = 0; i < toks.size(); ++i) {
        if (toks[i].kind == Tok::End) break;
        if (drop.count(i)) continue;
        if (auto it = replace.find(i); it != replace.end()) {
            out += it->second;
            continue;
        }
        if (toks[i].kind == Tok::Space) {
            if (toks[i].text.find('\n') != std::string::npos) {
                if (!out.empty() && out.back() != '\n') out += '\n';
            } else if (!out.empty() && out.back() != ' ' && out.back() != '\n') {
                out += ' ';
            }
            continue;
        }
        if (toks[i].kind == Tok::String || toks[i].kind == Tok::LineComment ||
            toks[i].kind == Tok::BlockComment) {
            out.append(src, toks[i].begin, toks[i].end - toks[i].begin);
            continue;
        }
        out.append(src, toks[i].begin, toks[i].end - toks[i].begin);
    }
    return out;
}
size_t nsig(const std::vector<Token>& toks, size_t from) {
    const size_t n = toks.size();
    size_t k = from;
    while (k < n && (toks[k].kind == Tok::Space || toks[k].kind == Tok::LineComment ||
                     toks[k].kind == Tok::BlockComment))
        ++k;
    return k;
}
bool matchesAny(const Token& t, const char* const* list, size_t count) {
    for (size_t i = 0; i < count; ++i)
        if (t.text == list[i]) return true;
    return false;
}
constexpr size_t kOpCount = 18;
bool isValueOperator(const Token& t) {
    static const char* const ops[kOpCount] = {
        "+", "-", "*", "/", "%", "^", "#", ".", ":", "?",
        "=", "==", "~=", "<", "<=", ">", ">=", ","
    };
    return t.kind == Tok::Symbol && matchesAny(t, ops, kOpCount);
}
constexpr size_t kEndCount = 16;
bool closesStatement(const Token& t) {
    static const char* const kws[kEndCount] = {
        "end", "until", "else", "elseif", "then", "in", "local", "if",
        "for", "while", "do", "return", "break", "goto", "function", "repeat"
    };
    if (t.kind == Tok::Symbol) return t.text == ";";
    return t.kind == Tok::Name && matchesAny(t, kws, kEndCount);
}
bool opensStatement(const Token& t) {
    if (t.kind != Tok::Name) return false;
    if (!lua::isKeyword(t.text)) return true;
    return t.text == "nil" || t.text == "true" || t.text == "false";
}
constexpr size_t kJoinCount = 3;
bool joinsValue(const Token& t) {
    static const char* const kws[kJoinCount] = {"and", "or", "not"};
    if (t.kind == Tok::Name) return matchesAny(t, kws, kJoinCount);
    return t.kind == Tok::Symbol &&
           (t.text == "." || t.text == ".." || t.text == "...");
}
size_t scanExpressionEnd(const std::vector<Token>& toks, size_t from) {
    const size_t n = toks.size();
    int brackets = 0;
    int blocks = 0;
    size_t last = kNone;
    bool pendingDo = false;
    for (size_t i = from; i < n; ++i) {
        const Token& t = toks[i];
        if (t.kind == Tok::End) return kNone;
        if (t.kind == Tok::Space) {
            if (t.text.find('\n') == std::string::npos) continue;
            if (brackets != 0 || blocks != 0) continue;
            if (last == kNone || isValueOperator(toks[last]) || joinsValue(toks[last]))
                return kNone;
            const size_t next = nsig(toks, i + 1);
            if (next >= n || closesStatement(toks[next])) return last;
            if (opensStatement(toks[next])) return last;
            if (joinsValue(toks[next])) continue;
            return kNone;
        }
        if (t.kind == Tok::LineComment || t.kind == Tok::BlockComment) return kNone;
        if (t.kind == Tok::Name) {
            const std::string& w = t.text;
            if (w == "function") {

                if (last != kNone && brackets == 0 && blocks == 0) return kNone;
                ++blocks;
            } else if (w == "end" || w == "until") {
                if (blocks == 0) return last;
                --blocks;
            } else if (w == "do") {
                if (blocks == 0 && brackets == 0) return kNone;
                if (!pendingDo) ++blocks;
                pendingDo = false;
            } else if (w == "if" || w == "for" || w == "while" || w == "repeat") {
                if (blocks == 0 && brackets == 0) return kNone;

                if (w == "for" || w == "while") pendingDo = true;
                ++blocks;
            } else if (w == "then" || w == "else" || w == "elseif" || w == "in") {
                if (blocks == 0) return last;
            } else if (blocks == 0 && brackets == 0 && lua::isKeyword(w) &&
                       w != "nil" && w != "true" && w != "false" && !joinsValue(t)) {
                return kNone;
            }
            last = i;
            continue;
        }
        if (t.kind == Tok::Symbol) {
            const std::string& s = t.text;
            if (s == "{" || s == "[" || s == "(") {
                ++brackets;
            } else if (s == "}" || s == "]" || s == ")") {
                if (brackets == 0) return last;
                --brackets;
            } else if (brackets == 0 && blocks == 0 && s == ";") {
                return last;
            } else if (brackets == 0 && blocks == 0 && s == ",") {
                return kNone;
            }
            last = i;
            continue;
        }
        last = i;
    }
    return kNone;
}
bool mentionsName(const std::string& text, const std::string& name) {
    size_t at = text.find(name);
    while (at != std::string::npos) {
        const bool leftOk = at == 0 || !(std::isalnum(static_cast<unsigned char>(text[at - 1])) ||
                                         text[at - 1] == '_');
        const size_t after = at + name.size();
        const bool rightOk = after >= text.size() ||
                             !(std::isalnum(static_cast<unsigned char>(text[after])) ||
                               text[after] == '_');
        if (leftOk && rightOk) return true;
        at = text.find(name, at + 1);
    }
    return false;
}
constexpr size_t kUnproven = static_cast<size_t>(-1);
size_t declarationEnd(const std::string& src, const std::vector<Token>& toks,
                      size_t localTok, size_t lastName) {
    const size_t next = significantIndex(toks, lastName + 1);
    if (next >= toks.size() || toks[next].kind != Tok::Symbol || toks[next].text != "=")
        return statementEnd(toks, localTok, lastName);
    const size_t value = significantIndex(toks, next + 1);
    if (value >= toks.size()) return statementEnd(toks, localTok, lastName);
    const size_t vend = scanExpressionEnd(toks, value);
    if (vend == kUnproven || !statementEndsHere(src, toks, vend)) return kUnproven;
    return vend;
}
std::string collapseExplodedTables(const std::string& src, int& collapsed) {
    const std::vector<Token> toks = lua::tokenize(src);
    const size_t n = toks.size();
    std::set<size_t> drop;
    std::map<size_t, std::string> replace;
    for (size_t i = 0; i + 3 < n; ++i) {
        if (toks[i].kind != Tok::Name || lua::isKeyword(toks[i].text)) continue;
        const size_t eq = significantIndex(toks, i + 1);
        if (eq >= n || toks[eq].kind != Tok::Symbol || toks[eq].text != "=") continue;
        const size_t open = significantIndex(toks, eq + 1);
        if (open >= n || toks[open].kind != Tok::Symbol || toks[open].text != "{") continue;
        const size_t close = significantIndex(toks, open + 1);
        if (close >= n || toks[close].kind != Tok::Symbol || toks[close].text != "}") continue;
        if (!statementEndsHere(src, toks, close)) continue;
        const std::string name = toks[i].text;
        std::vector<std::pair<std::string, std::string>> fields;
        size_t k = close + 1;
        bool usable = true;
        while (k < n) {
            const size_t base = nsig(toks, k);
            if (base >= n || toks[base].kind != Tok::Name || toks[base].text != name) break;
            const size_t dot = nsig(toks, base + 1);
            if (dot >= n || toks[dot].kind != Tok::Symbol || toks[dot].text != ".") break;
            const size_t fname = nsig(toks, dot + 1);
            if (fname >= n || toks[fname].kind != Tok::Name ||
                lua::isKeyword(toks[fname].text))
                break;
            const size_t feq = nsig(toks, fname + 1);
            if (feq >= n || toks[feq].kind != Tok::Symbol || toks[feq].text != "=") break;
            const size_t vbeg = nsig(toks, feq + 1);
            if (vbeg >= n) break;
            const size_t vend = scanExpressionEnd(toks, vbeg);
            if (vend == kUnproven) break;
            if (!statementEndsHere(src, toks, vend)) break;
            const std::string value = src.substr(toks[vbeg].begin,
                                                 toks[vend].end - toks[vbeg].begin);
            if (mentionsName(value, name)) {
                usable = false;
                break;
            }
            fields.emplace_back(toks[fname].text, value);
            k = vend + 1;
        }
        if (!usable || fields.size() < 2) continue;
        for (size_t p = close + 1; p < k; ++p)
            if (toks[p].kind == Tok::LineComment || toks[p].kind == Tok::BlockComment)
                usable = false;
        if (!usable) continue;
        std::string ctor = "{ ";
        for (size_t f = 0; f < fields.size(); ++f) {
            if (f) ctor += ", ";
            ctor += fields[f].first + " = " + fields[f].second;
        }
        ctor += " }";
        replace[i] = name + " = " + ctor;
        drop.insert(eq);
        for (size_t p = i + 1; p <= close; ++p) drop.insert(p);
        for (size_t p = close + 1; p < k; ++p) drop.insert(p);
        ++collapsed;
        i = k - 1;
    }
    if (replace.empty()) return src;
    return rebuildCollapsed(src, toks, drop, replace);
}
std::string simplifyLocals(const std::string& src, int& inlined, int& deadStores,
                           int& tables) {
    std::string working = src;
    for (int round = 0; round < 32; ++round) {
        const std::string next = collapseExplodedTables(working, tables);
        if (next == working) break;
        working = next;
    }
    for (int round = 0;; ++round) {
        const std::vector<Token> toks = lua::tokenize(working);
        const size_t n = toks.size();
        if (round >= (n > 1000000 ? 24 : 400)) break;
        std::map<size_t, std::vector<size_t>> declLists;
        const std::map<std::string, NameUses> index = indexNames(toks, declLists);
        const std::vector<int> depths = functionDepths(toks);
        std::set<size_t> drop;
        std::map<size_t, std::string> replace;
        std::set<size_t> declClaimed;
        int roundInlined = 0;
        int roundDead = 0;
        for (const auto& [name, u] : index) {
            if (u.ambiguous || u.declName == kNone) continue;
            bool captured = false;
            for (size_t w : u.writes)
                if (depths[w] != depths[u.declName]) captured = true;
            for (size_t r : u.reads)
                if (depths[r] != depths[u.declName]) captured = true;
            if (captured) continue;
            if (u.writes.size() == 1 && u.reads.size() == 1 &&
                !declClaimed.count(u.declLocal)) {
                const size_t assign = u.writes[0];
                const size_t assignEq = significantIndex(toks, assign + 1);
                const size_t value = significantIndex(toks, assignEq + 1);
                const size_t use = u.reads[0];
                const Token& v = toks[value < n ? value : kNone];
                const bool literal = v.kind == Tok::String || v.kind == Tok::Number ||
                                     (v.kind == Tok::Name && (v.text == "true" ||
                                                              v.text == "false"));
                const bool globalName = v.kind == Tok::Name && !lua::isKeyword(v.text);
                if (value < n && (literal || globalName) && use > assign &&
                    statementEndsHere(working, toks, value)) {
                    const size_t afterUse = significantIndex(toks, use + 1);
                    if (afterUse >= n || toks[afterUse].kind != Tok::Symbol ||
                        toks[afterUse].text != ":" || globalName) {
                        bool earlierUse = false;
                        for (size_t r : u.reads)
                            if (r < assign) earlierUse = true;
                        if (earlierUse) continue;
                        const size_t assignEnd = statementEnd(toks, assign, value);
                        for (size_t k = assign; k <= assignEnd && k < n; ++k) drop.insert(k);
                        drop.insert(u.declName);
                        replace[use] = working.substr(toks[value].begin,
                                                      toks[value].end - toks[value].begin);
                        declClaimed.insert(u.declLocal);
                        ++roundInlined;
                    }
                }
            }
            if (u.writes.size() < 2) continue;
            for (size_t w = 0; w + 1 < u.writes.size(); ++w) {
                const size_t from = u.writes[w];
                const size_t to = u.writes[w + 1];
                size_t nextRead = n;
                for (size_t r : u.reads) {
                    if (r > from && r < to) { nextRead = r; break; }
                    if (r >= to) break;
                }
                if (nextRead != n) continue;
                const size_t writeEq = significantIndex(toks, from + 1);
                const size_t value = significantIndex(toks, writeEq + 1);
                if (value >= n || !isSideEffectFreeValue(toks[value])) continue;
                const size_t stmtEnd = statementEnd(toks, from, value);
                if (!statementEndsHere(working, toks, value)) continue;
                for (size_t k = from; k <= stmtEnd && k < n; ++k) {
                    if (toks[k].kind == Tok::End) break;
                    if (replace.count(k)) continue;
                    drop.insert(k);
                }
                ++roundDead;
            }
        }
        for (const auto& [declLocal, names] : declLists) {
            const size_t last = names.back();
            std::vector<size_t> survivors;
            bool removed = false;
            for (size_t p : names) {
                if (drop.count(p)) {
                    removed = true;
                    continue;
                }
                survivors.push_back(p);
            }
            if (!removed) continue;
            if (survivors.empty()) {
                const size_t declEnd = declarationEnd(working, toks, declLocal, last);
                if (declEnd == kUnproven) {
                    for (size_t p : names) drop.erase(p);
                    continue;
                }
                for (size_t k = declLocal; k <= declEnd && k < n; ++k) drop.insert(k);
            } else {
                const size_t first = names.front();
                std::string list;
                for (size_t i = 0; i < survivors.size(); ++i) {
                    if (i) list += ", ";
                    list += working.substr(toks[survivors[i]].begin,
                                           toks[survivors[i]].end - toks[survivors[i]].begin);
                }
                for (size_t k = first + 1; k <= last && k < n; ++k) drop.insert(k);
                drop.erase(first);
                replace[first] = list;
            }
        }
        if (roundInlined == 0 && roundDead == 0) break;
        inlined += roundInlined;
        deadStores += roundDead;
        working = rebuildCollapsed(working, toks, drop, replace);
    }
    return working;
}
std::set<std::string> collectLocalNames(const std::vector<Token>& toks) {
    const size_t n = toks.size();
    std::set<std::string> locals;
    for (size_t i = 0; i < n; ++i) {
        if (toks[i].kind != Tok::Name || toks[i].text != "local") continue;
        size_t k = significantIndex(toks, i + 1);
        while (k < n && toks[k].kind == Tok::Name && !lua::isKeyword(toks[k].text)) {
            locals.insert(toks[k].text);
            const size_t afterName = significantIndex(toks, k + 1);
            if (afterName < n && toks[afterName].kind == Tok::Symbol &&
                toks[afterName].text == ",") {
                k = significantIndex(toks, afterName + 1);
                continue;
            }
            break;
        }
    }
    return locals;
}
std::map<std::string, int> countNameTokens(const std::vector<Token>& toks) {
    std::map<std::string, int> counts;
    for (size_t i = 0; i < toks.size(); ++i) {
        if (toks[i].kind != Tok::Name) continue;
        size_t j = i;
        while (j > 0 && toks[j - 1].kind == Tok::Space) --j;
        if (j > 0 && toks[j - 1].kind == Tok::Symbol && toks[j - 1].text == ".") continue;
        ++counts[toks[i].text];
    }
    return counts;
}
std::map<std::string, std::string> buildRenameMap(const std::vector<Token>& toks,
                                                  const std::set<std::string>& localNames,
                                                  int& skipped) {
    const std::set<std::string> locals = collectLocalNames(toks);
    const std::map<std::string, int> useCounts = countNameTokens(toks);
    std::map<std::string, std::vector<std::string>> bindings;
    std::map<std::string, std::string> suffixes;
    for (size_t i = 0; i < toks.size(); ++i) {
        if (toks[i].kind != Tok::Name) continue;
        std::string suffix;
        if (!isSyntheticName(toks[i].text, suffix)) continue;
        if (!locals.count(toks[i].text)) continue;
        const size_t after = significantIndex(toks, i + 1);
        if (after >= toks.size() || toks[after].kind != Tok::Symbol || toks[after].text != "=")
            continue;
        std::string base = nameFromBinding(toks, i);
        if (base.empty()) {
            ++skipped;
            continue;
        }
        const auto seen = useCounts.find(base);
        if (seen != useCounts.end() && seen->second > 0) {
            ++skipped;
            continue;
        }
        bindings[toks[i].text].push_back(base);
        suffixes[toks[i].text] = suffix;
    }
    for (auto& [name, bases] : bindings) {
        if (bases.empty()) {
            ++skipped;
            continue;
        }
        std::string suffixDummy;
        const std::string& base = bases.front();
        if (isSyntheticName(base, suffixDummy)) {
            ++skipped;
            continue;
        }
    }
    std::map<std::string, std::string> rename;
    std::set<std::string> used;
    for (auto& [name, bases] : bindings) {
        if (bases.empty()) continue;
        const std::string& base = bases.front();
        const std::string stem = base + suffixes[name];
        std::string target = stem;
        for (int bump = 2; localNames.count(target) || used.count(target) ||
                              lua::isKeyword(target); ++bump) {
            target = stem + std::to_string(bump);
        }
        rename[name] = target;
        used.insert(target);
    }
    return rename;
}
std::string reindent(const std::string& src, const std::vector<Token>& toks, int& reindented) {
    size_t crlf = 0;
    size_t lf = 0;
    for (size_t k = 0; k + 1 < src.size(); ++k) {
        if (src[k] != '\n') continue;
        if (k > 0 && src[k - 1] == '\r') ++crlf; else ++lf;
    }
    const std::string eol = (crlf > lf) ? "\r\n" : "\n";
    std::string out;
    int level = 0;
    bool lineStarted = false;
    size_t i = 0;
    while (i < toks.size() && toks[i].kind != Tok::End) {
        const Token& t = toks[i];
        if (t.kind == Tok::Space) {
            if (t.text.find('\n') == std::string::npos) {
                if (lineStarted) out += t.text;
                ++i;
                continue;
            }
            int newlines = 0;
            for (char c : t.text) if (c == '\n') ++newlines;
            for (int k = 0; k < newlines; ++k) {
                if (k > 0 || !out.empty()) out += eol;
            }
            lineStarted = false;
            ++i;
            continue;
        }
        if (t.kind == Tok::Name) {
            const std::string& kw = t.text;
            const bool closes = (kw == "end" || kw == "until");
            const bool branches = (kw == "else" || kw == "elseif");
            bool dedented = false;
            if (!lineStarted && (closes || branches) && level > 0) {
                --level;
                dedented = true;
                ++reindented;
            }
            if (!lineStarted) {
                out.append(static_cast<size_t>(level) * 4, ' ');
                lineStarted = true;
            }
            out += t.text;
            if (kw == "function" || kw == "do" || kw == "repeat" || kw == "then") {
                ++level;
            } else if (closes) {
                if (!dedented) --level;
            } else if (branches) {
                ++level;
            }
            ++i;
            continue;
        }
        if (!lineStarted) {
            out.append(static_cast<size_t>(level) * 4, ' ');
            lineStarted = true;
        }
        out.append(src, t.begin, t.end - t.begin);
        ++i;
    }
    if (level != 0) return {};
    return out;
}
bool isBalanced(const std::vector<Token>& toks, int& gotoCount) {
    int depth = 0;
    gotoCount = 0;
    for (const auto& t : toks) {
        if (t.kind != Tok::Name) continue;
        if (t.text == "goto") ++gotoCount;
        if (t.text == "function" || t.text == "do" || t.text == "repeat" || t.text == "if") {
            ++depth;
        } else if (t.text == "end" || t.text == "until") {
            if (--depth < 0) return false;
        }
    }
    return depth == 0;
}
bool hasUnterminatedString(const std::vector<Token>& toks) {
    for (const auto& t : toks) {
        if (t.kind != Tok::String && t.kind != Tok::BlockComment) continue;
        if (!t.closed) return true;
    }
    return false;
}
bool isBannerLine(const std::string& line);
size_t bannerEnd(const std::string& src, const std::vector<Token>& toks) {
    size_t cut = 0;
    bool named = false;
    for (const auto& t : toks) {
        if (t.kind == Tok::Space) continue;
        if (t.kind == Tok::LineComment || t.kind == Tok::BlockComment) {
            if (isBannerLine(src.substr(t.begin, t.end - t.begin))) named = true;
            cut = t.end;
            continue;
        }
        break;
    }
    return named ? cut : 0;
}
bool isBannerLine(const std::string& line) {
    static const char* markers[] = {
        "AI CLEANUP",
        "Decompiled Lua",
        "SHX_LABEL_XX",
        "no visible label",
        "decompiler comments",
        "Fix indentation",
        "Rename SHX",
        "Replace goto/label",
        "Move ::",
    };
    for (const char* m : markers) {
        if (line.find(m) != std::string::npos) return true;
    }
    return false;
}
std::string stripBanners(const std::string& src, int& removed) {
    const std::vector<Token> toks = lua::tokenize(src);
    std::vector<Token> keep;
    keep.reserve(toks.size());
    size_t i = 0;
    while (i < toks.size()) {
        if (toks[i].kind == Tok::End) break;
        if (toks[i].kind != Tok::LineComment) {
            keep.push_back(toks[i]);
            ++i;
            continue;
        }
        std::vector<size_t> group;
        size_t k = i;
        for (;;) {
            if (toks[k].kind != Tok::LineComment) break;
            group.push_back(k);
            size_t next = k + 1;
            while (next < toks.size() && toks[next].kind == Tok::Space) ++next;
            if (next >= toks.size() || toks[next].kind != Tok::LineComment) break;
            k = next;
        }
        bool allBanner = group.size() >= 2;
        for (size_t idx : group) {
            if (!isBannerLine(src.substr(toks[idx].begin, toks[idx].end - toks[idx].begin))) {
                allBanner = false;
                break;
            }
        }
        if (allBanner) {
            ++removed;
            for (size_t idx = i; idx <= k; ++idx) {
                if (toks[idx].kind != Tok::LineComment) keep.push_back(toks[idx]);
            }
            i = k + 1;
            continue;
        }
        for (size_t idx = i; idx <= k; ++idx) keep.push_back(toks[idx]);
        i = k + 1;
    }
    std::string out;
    out.reserve(src.size());
    for (const auto& t : keep) {
        if (t.kind == Tok::End) break;
        out.append(src, t.begin, t.end - t.begin);
    }
    std::string collapsed;
    collapsed.reserve(out.size());
    size_t p = 0;
    while (p < out.size()) {
        if (out[p] == '\r') { ++p; continue; }
        if (out[p] == '\n') {
            int blanks = 0;
            size_t j = p;
            while (j < out.size() && (out[j] == ' ' || out[j] == '\t' || out[j] == '\r')) ++j;
            if (j < out.size() && out[j] == '\n') {
                ++blanks;
                p = j + 1;
                if (blanks >= 2) continue;
                collapsed += '\n';
                continue;
            }
            ++p;
            continue;
        }
        collapsed += out[p];
        ++p;;
    }
    return collapsed;
}
}
CleanupResult cleanupLua(const std::string& source) {
    CleanupResult result;
    result.text = source;
    if (source.empty()) return result;
    std::vector<Token> toks = lua::tokenize(source);
    if (hasUnterminatedString(toks)) return result;
    isBalanced(toks, result.gotoLabels);
    std::string working = source;
    {
        int extra = 0;
        const std::string stripped = stripBanners(working, extra);
        if (stripped != working) {
            working = stripped;
            result.bannerRemoved += extra;
            result.changed = true;
            toks = lua::tokenize(working);
        }
    }
    if (const size_t cut = bannerEnd(working, toks); cut > 0 && cut < working.size()) {
        working = working.substr(cut);
        const size_t first = working.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return result;
        working = working.substr(first);
        result.bannerRemoved += 1;
        result.changed = true;
        toks = lua::tokenize(working);
    }
    int inlined = 0;
    int deadStores = 0;
    int tables = 0;
    if (std::string collapsed = simplifyLocals(working, inlined, deadStores, tables);
        collapsed != working) {
        working = std::move(collapsed);
        result.inlinedAliases = inlined;
        result.deadStores = deadStores;
        result.collapsedTables = tables;
        result.changed = true;
        toks = lua::tokenize(working);
        if (hasUnterminatedString(toks)) {
            result.text = source;
            result.changed = false;
            return result;
        }
    }
    int skipped = 0;
    const auto rename = buildRenameMap(toks, collectLocalNames(toks), skipped);
    result.ambiguousVars = skipped;
    if (!rename.empty()) {
        std::string renamed;
        renamed.reserve(working.size());
        for (const auto& t : toks) {
            if (t.kind == Tok::End) break;
            if (t.kind == Tok::Name) {
                if (auto it = rename.find(t.text); it != rename.end()) {
                    renamed += it->second;
                    continue;
                }
            }
            renamed.append(working, t.begin, t.end - t.begin);
        }
        working = std::move(renamed);
        result.renamedVars = static_cast<int>(rename.size());
        result.changed = true;
        toks = lua::tokenize(working);
    }
    int reindented = 0;
    if (std::string spaced = reindent(working, toks, reindented); !spaced.empty()) {
        if (spaced != working) {
            working = std::move(spaced);
            result.reindentedLines = reindented;
            result.changed = true;
        }
    }
    if (hasUnterminatedString(lua::tokenize(working))) {
        result.text = source;
        result.changed = false;
        result.bannerRemoved = 0;
        result.renamedVars = 0;
        result.reindentedLines = 0;
        result.ambiguousVars = 0;
        result.inlinedAliases = 0;
        return result;
    }
    result.text = std::move(working);
    return result;
}
CleanupStats cleanupLuaTree(const std::string& rootIn, const std::string& rootOut) {
    CleanupStats stats;
    std::error_code ec;
    std::vector<fs::path> files;
    for (auto& e : fs::recursive_directory_iterator(rootIn, ec)) {
        if (e.is_regular_file() && endsWith(toLower(e.path().extension().string()), ".lua"))
            files.push_back(e.path());
    }
    if (ec) {
        LOG("figyelmeztetes - a " + rootIn + " bejarasa megszakadt: " + ec.message(),
            LogLevel::WARNING);
        ++stats.suspicious;
    }
    std::sort(files.begin(), files.end());
    for (const auto& in : files) {
        const fs::path out = fs::path(rootOut) / fs::relative(in, rootIn);
        auto data = readFileBytes(in.string());
        if (!data) {
            ++stats.suspicious;
            continue;
        }
        const std::string source(data->begin(), data->end());
        const CleanupResult r = cleanupLua(source);
        if (!r.changed) ++stats.unchanged;
        fs::create_directories(out.parent_path(), ec);
        const std::string& text = r.text;
        if (!writeFileBytes(out.string(), std::vector<uint8_t>(text.begin(), text.end()))) {
            ++stats.suspicious;
            continue;
        }
        ++stats.files;
        stats.bannerRemoved += r.bannerRemoved;
        stats.renamedVars += r.renamedVars;
        stats.ambiguousVars += r.ambiguousVars;
        stats.gotoLabels += r.gotoLabels;
        stats.reindentedLines += r.reindentedLines;
        stats.inlinedAliases += r.inlinedAliases;
    stats.deadStores += r.deadStores;
    stats.collapsedTables += r.collapsedTables;
    }
    return stats;
}
} 