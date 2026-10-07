#pragma once
#include <string>
namespace fivem {
struct NamingStats {
    int files = 0;
    int filesChanged = 0;
    int filesSkipped = 0;
    int registers = 0;
    int proposed = 0;
    int accepted = 0;
    int rejected = 0;
    int renamed = 0;
    int luacChecked = 0;
    int luacReverted = 0;
};
bool aiNamingAvailable();
NamingStats runAiNaming(const std::string& cleanDir);
}
