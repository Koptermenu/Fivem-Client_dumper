#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace fivem {
struct CleanupStats {
    int files = 0;
    int unchanged = 0;
    int bannerRemoved = 0;
    int renamedVars = 0;
    int ambiguousVars = 0;
    int gotoLabels = 0;
    int reindentedLines = 0;
    int inlinedAliases = 0;
    int suspicious = 0;
};
struct CleanupResult {
    bool changed = false;
    int bannerRemoved = 0;
    int renamedVars = 0;
    int ambiguousVars = 0;
    int gotoLabels = 0;
    int reindentedLines = 0;
    int inlinedAliases = 0;
    std::string text;
};
CleanupResult cleanupLua(const std::string& source);
CleanupStats cleanupLuaTree(const std::string& rootIn, const std::string& rootOut);
} 