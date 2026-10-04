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

// unluac names its synthetic locals L<slot>_<n> / SHX<slot>_<n>. The trailing group is
// what makes a readable name unique within a file without any scope analysis.
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

// Index of the next token that is not whitespace or a comment.
size_t significantIndex(const std::vector<Token>& toks, size_t from) {
    const size_t n = toks.size();
    size_t k = from;
    while (k < n && (toks[k].kind == Tok::Space || toks[k].kind == Tok::LineComment ||
                     toks[k].kind == Tok::BlockComment)) {
        ++k;
    }
    return k;
}

// Derives a readable name from the expression a local is bound to. `nameIdx` points at
// the name; the '=' that follows is consumed before the expression is inspected.
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

// Names introduced by a `local` declaration list, so a synthetic local can be told apart
// from a global that happens to look synthetic.
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

// How often a bare identifier appears in the file.
int identifierUseCount(const std::vector<Token>& toks, const std::string& name) {
    int count = 0;
    for (const auto& t : toks) {
        if (t.kind == Tok::Name && t.text == name) ++count;
    }
    return count;
}

// "<synthetic name> -> readable name".
//
// Only the bases that do not appear in the binding expression itself can be reused.
// `SHX0_1 = {}` may become `table1`, because the right-hand side never reads the name
// `table`. `SHX7_1 = RegisterNetEvent` must not become `RegisterNetEvent`: after the
// rename the right-hand side would resolve to the just-declared local instead of the
// global, so the capture silently turns into `local = local` and the value is lost.
// Without scope analysis the name cannot be reused there, and a suffixed
// `RegisterNetEvent14` is no more readable than the original, so those are left alone.
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

        // Only an actual initialiser is a value binding. In `local a, b = f()` the `a`
        // slot has none, and treating it as "bound to a" would name every such local
        // after whatever identifier happens to follow the comma.
        const size_t after = significantIndex(toks, i + 1);
        if (after >= toks.size() || toks[after].kind != Tok::Symbol || toks[after].text != "=")
            continue;

        // Whether the right-hand side reads the base name decides whether the base can
        // ever be reused: `= {}` does not, `= RegisterNetEvent` does.
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

    std::map<std::string, std::string> rename;
    std::set<std::string> used;
    for (auto& [name, bases] : bindings) {
        if (bases.empty()) continue;
        const std::string& base = bases.front();
        // The slot number keeps the readable name unique, so a renamed table local
        // (`table1`) cannot take over the global `table` that other code still reads.
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

// Re-indents to four spaces per nesting level.
//
// Level is driven by the block keywords: function/do/repeat/then open a level,
// end/until close one. A closing keyword that starts a line is written one level out;
// else/elseif are written out but immediately open their body again.
//
// The source's dominant line ending is kept, so a CRLF file does not end up with a mix.
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

            // A closing keyword that starts a line is written one level out. That
            // outdent is the same step as closing the block, so it must not be counted
            // twice - otherwise the level runs negative and the whole pass gives up.
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
                ++level;  // the branch body sits one level in again
            }
            ++i;
            continue;
        }

        if (!lineStarted) {
            out.append(static_cast<size_t>(level) * 4, ' ');
            lineStarted = true;
        }
        // Comments and literals are copied byte for byte: a comment token's text field has
        // its markers stripped, so the source range is the only safe source of truth.
        out.append(src, t.begin, t.end - t.begin);
        ++i;
    }

    if (level != 0) return {};  // unbalanced: refuse the re-indent
    return out;
}

bool isBalanced(const std::vector<Token>& toks, int& gotoCount) {
    int depth = 0;
    gotoCount = 0;
    for (const auto& t : toks) {
        if (t.kind != Tok::Name) continue;
        if (t.text == "goto") ++gotoCount;
        if (t.text == "function" || t.text == "do" || t.text == "repeat" || t.text == "then") {
            ++depth;
        } else if (t.text == "end" || t.text == "until") {
            if (--depth < 0) return false;
        }
    }
    return depth == 0;
}

// The lexer records whether a string or block comment actually found its terminator.
bool hasUnterminatedString(const std::vector<Token>& toks) {
    for (const auto& t : toks) {
        if (t.kind != Tok::String && t.kind != Tok::BlockComment) continue;
        if (!t.closed) return true;
    }
    return false;
}

// End offset of the decompiler banner: the leading run of blank lines and comments
// before the first statement. Comments further down the file are kept.
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

} // namespace

CleanupResult cleanupLua(const std::string& source) {
    CleanupResult result;
    result.text = source;
    if (source.empty()) return result;

    std::vector<Token> toks = lua::tokenize(source);

    // An unterminated literal makes the token stream untrustworthy, so nothing is done.
    // A block-balance mismatch is common in decompiled output and only affects the
    // re-indent step, which is the one part that needs nesting levels.
    if (hasUnterminatedString(toks)) return result;
    isBalanced(toks, result.gotoLabels);

    std::string working = source;

    if (const size_t cut = bannerEnd(toks); cut > 0 && cut < working.size()) {
        working = working.substr(cut);
        // Drop the blank lines the banner leaves behind, so the file starts on code.
        const size_t first = working.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return result;
        working = working.substr(first);
        result.bannerRemoved = 1;
        result.changed = true;
        toks = lua::tokenize(working);
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

    // Final gate: the rewritten token stream must still be closed.
    if (hasUnterminatedString(lua::tokenize(working))) {
        result.text = source;
        result.changed = false;
        result.bannerRemoved = 0;
        result.renamedVars = 0;
        result.reindentedLines = 0;
        result.ambiguousVars = 0;
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
    }
    return stats;
}

} // namespace fivem