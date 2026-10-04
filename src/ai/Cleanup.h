#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace fivem {

struct CleanupStats {
    int files = 0;
    int unchanged = 0;    // already clean, nothing to rewrite
    int bannerRemoved = 0;
    int renamedVars = 0;
    int ambiguousVars = 0;
    int gotoLabels = 0;   // goto/label blocks reported, never rewritten
    int reindentedLines = 0;
    int suspicious = 0;   // unreadable source or an unwritable output
};

struct CleanupResult {
    bool changed = false;
    int bannerRemoved = 0;
    int renamedVars = 0;
    int ambiguousVars = 0;
    int gotoLabels = 0;
    int reindentedLines = 0;
    std::string text;
};

// Deterministic readability pass over decompiled Lua.
//
// Renames unluac's synthetic locals (L0_1, SHX0_1, ...) to a name taken from the
// expression they are first bound to, re-indents to four spaces per block and drops the
// decompiler's leading banner. Nothing inside a string or a comment is ever touched.
//
// goto/label blocks are reported rather than rewritten: converting them to loops without
// a real parser changes control flow, and silently altering control flow in recovered
// source is worse than leaving it readable.
CleanupResult cleanupLua(const std::string& source);

// Applies cleanup to every .lua file under root, writing to rootOut. Files that would
// look suspicious (broken keyword balance, unterminated string, a rename that collides)
// are copied verbatim and counted, so the output is never worse than the input.
CleanupStats cleanupLuaTree(const std::string& rootIn, const std::string& rootOut);

} // namespace fivem