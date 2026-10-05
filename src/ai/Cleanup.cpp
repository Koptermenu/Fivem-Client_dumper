#include "Cleanup.h"
#include "LuaLexer.h"
#include "../core/Logger.h"
#include "../utils/Str.h"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <map>
#include <set>
namespace fs = std::filesystem;
namespace fivem {
namespace {
using lua::Tok;
using lua::Token;
bool isSyntheticName(const std::string& name, std::string& suffix) {
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
std::string nameFromBinding(const std::vector<Token>& toks, size_t nameIdx) {
    const size_t n = toks.size();
    const size_t assign = significantIndex(toks, nameIdx + 1);
    if (assign >= n || toks[assign].kind != Tok::Symbol || toks[assign].text != "=") return "";
    const size_t i = significantIndex(toks, assign + 1);
    if (i >= n) return "";
    if (toks[i].kind == Tok::Name && toks[i].text == "function") return "callback";
    if (toks[i].kind == Tok::Symbol && toks[i].text == "{") return "table";
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
std::string inlineAliases(const std::string& src, int& inlined) {
    std::string working = src;
    for (int round = 0; round < 64; ++round) {
        const std::vector<Token> toks = lua::tokenize(working);
        const std::set<std::string> declared = collectLocalNames(toks);
        bool progress = false;
        for (const auto& name : declared) {
            InlineEdit edit;
            if (!planInlineAlias(working, toks, name, edit)) continue;
            working = applyInline(working, toks, edit);
            ++inlined;
            progress = true;
            break;
        }
        if (!progress) break;
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
int identifierUseCount(const std::vector<Token>& toks, const std::string& name) {
    int count = 0;
    for (const auto& t : toks) {
        if (t.kind == Tok::Name && t.text == name) ++count;
    }
    return count;
}
std::map<std::string, std::string> buildRenameMap(const std::vector<Token>& toks,
                                                  const std::set<std::string>& localNames,
                                                  int& skipped) {
    const std::set<std::string> locals = collectLocalNames(toks);
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
        if (identifierUseCount(toks, base) > 0) {
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
size_t bannerEnd(const std::vector<Token>& toks) {
    size_t cut = 0;
    for (const auto& t : toks) {
        if (t.kind == Tok::Space) continue;
        if (t.kind == Tok::LineComment || t.kind == Tok::BlockComment) {
            cut = t.end;
            continue;
        }
        break;
    }
    return cut;
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
    if (const size_t cut = bannerEnd(toks); cut > 0 && cut < working.size()) {
        working = working.substr(cut);
        const size_t first = working.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return result;
        working = working.substr(first);
        result.bannerRemoved = 1;
        result.changed = true;
        toks = lua::tokenize(working);
    }
    int inlined = 0;
    if (std::string collapsed = inlineAliases(working, inlined); collapsed != working) {
        working = std::move(collapsed);
        result.inlinedAliases = inlined;
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
    }
    return stats;
}
} 