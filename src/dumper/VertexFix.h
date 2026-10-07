#pragma once
#include <string>

namespace fivem {
















struct VertexFixStats {
    bool ran = false;
    bool ok = false;
    int scanned = 0;
    int repaired = 0;
    int failed = 0;
    int files = 0;
    int written = 0;
    double seconds = 0.0;
    std::string message;
};

VertexFixStats runVertexFix(const std::string& root);

}