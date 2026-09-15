#pragma once

#include "Term.h"

#include <cstdint>
#include <string>
#include <chrono>
#include <atomic>
#include <cstdio>

namespace fivem {

// Simple thread-safe console progress bar (tqdm-style).
class ProgressBar {
public:
    ProgressBar(const std::string& label, uint64_t total)
        : label_(label), total_(total) {
        start_ = std::chrono::steady_clock::now();
        render();
    }

    void tick() {
        ++done_;
        render();
    }

    void addBytes(size_t n) {
        bytes_ += n;
        render();
    }

    void finish() {
        done_ = total_;
        render();
        std::printf("\n");
        std::fflush(stdout);
    }

private:
    void render() {
        auto now = std::chrono::steady_clock::now();
        // Throttle to ~20fps
        if (now - lastRender_ < std::chrono::milliseconds(50) && done_ < total_) return;
        lastRender_ = now;

        double frac = total_ ? static_cast<double>(done_) / static_cast<double>(total_) : 1.0;
        int filled = static_cast<int>(30 * frac);
        double secs = std::chrono::duration<double>(now - start_).count();
        double kbs = secs > 0.5 ? static_cast<double>(bytes_.load()) / 1024.0 / secs : 0.0;

        std::string bar;
        int i = 0;
        std::string fill;
        for (; i < filled && i < 30; ++i) fill += '#';
        std::string rest;
        for (; i < 30; ++i) rest += '-';
        bar += CLR(term::GREEN) + fill + CLR(term::DIM) + rest + CLR(term::RESET);

        char speed[48] = "";
        uint64_t b = bytes_.load();
        if (b > 0)
            std::snprintf(speed, sizeof(speed), " | %llu B @ %.1f KB/s",
                          static_cast<unsigned long long>(b), kbs);

        std::printf("\r%s%s [%s] %s%3.0f%%%s (%llu/%llu) %.1fs%s%s%s",
                    CLR(term::DIM), label_.c_str(), bar.c_str(),
                    CLR(term::GREEN), frac * 100.0, CLR(term::RESET),
                    static_cast<unsigned long long>(done_.load()),
                    static_cast<unsigned long long>(total_), secs,
                    CLR(term::DIM), speed, CLR(term::RESET));
        std::fflush(stdout);
    }

    std::string label_;
    uint64_t total_;
    std::atomic<uint64_t> done_{0};
    std::atomic<uint64_t> bytes_{0};
    std::chrono::steady_clock::time_point start_;
    std::chrono::steady_clock::time_point lastRender_{};
};

} // namespace fivem
