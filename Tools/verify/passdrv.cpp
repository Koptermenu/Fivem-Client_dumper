





#include "ai/Cleanup.h"

#include <cstdio>
#include <string>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: pass <inputDir> <outputDir>\n");
        return 2;
    }
    const fivem::CleanupStats s = fivem::cleanupLuaTree(argv[1], argv[2]);
    std::printf(
        "{\"files\":%d,\"unchanged\":%d,\"bannerRemoved\":%d,\"renamedVars\":%d,"
        "\"ambiguousVars\":%d,\"gotoLabels\":%d,\"reindentedLines\":%d,"
        "\"inlinedAliases\":%d,\"deadStores\":%d,\"collapsedTables\":%d,"
        "\"suspicious\":%d}\n",
        s.files, s.unchanged, s.bannerRemoved, s.renamedVars, s.ambiguousVars,
        s.gotoLabels, s.reindentedLines, s.inlinedAliases, s.deadStores,
        s.collapsedTables, s.suspicious);
    return 0;
}