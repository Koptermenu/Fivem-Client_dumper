#pragma once
#ifdef _WIN32
#include <windows.h>
#endif
#include <cstdlib>
namespace fivem {
namespace term {
constexpr const char* RESET = "\033[0m";
constexpr const char* BOLD = "\033[1m";
constexpr const char* DIM = "\033[2m";
constexpr const char* RED = "\033[31m";
constexpr const char* GREEN = "\033[32m";
constexpr const char* YELLOW = "\033[33m";
constexpr const char* CYAN = "\033[36m";
inline bool& enabled() {
    static bool e = false;
    return e;
}
inline void enableColors() {
#ifdef _WIN32
    if (getenv("NO_COLOR")) return;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE || h == nullptr) return;
    DWORD mode = 0;
    if (!GetConsoleMode(h, &mode)) return;
    if (SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        enabled() = true;
#endif
}
}
}
#define CLR(code) (fivem::term::enabled() ? (code) : "")
