#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

#include "Term.h"

namespace fivem {

class ProgressBar {
public:
    ProgressBar(std::string label, size_t total)
        : label_(std::move(label)), total_(total ? total : 1) {
        start_ = std::chrono::steady_clock::now();
        lastRender_ = start_;
        render();
    }

    ~ProgressBar() {
        if (!finished_) finish();
    }

    void addBytes(size_t n) {
        bytes_.fetch_add(n, std::memory_order_relaxed);
    }

    void addExpected(size_t n) {
        expectedBytes_.fetch_add(n, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(mtx_);
        if (!finished_) render();
    }

    void tick() {
        done_.fetch_add(1, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(mtx_);
        if (finished_) return;
        auto now = std::chrono::steady_clock::now();
        auto since = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastRender_).count();
        if (since < 100 && done_.load() < total_) return;
        lastRender_ = now;
        render();
    }

    void finish() {
        std::lock_guard<std::mutex> lock(mtx_);
        if (finished_) return;
        finished_ = true;
        render();
        std::cout << "\n" << std::flush;
    }

private:
    static std::string formatBytes(double bytes) {
        static const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
        int u = 0;
        while (bytes >= 1024.0 && u < 5) {
            bytes /= 1024.0;
            ++u;
        }
        std::ostringstream ss;
        if (u == 0) {
            ss << static_cast<long long>(bytes) << " B";
        } else {
            ss << std::fixed << std::setprecision(2) << bytes << " " << units[u];
        }
        return ss.str();
    }

    static std::string formatSpeed(double bytesPerSec) {
        return formatBytes(bytesPerSec) + "/s";
    }

    static std::string formatDuration(double seconds) {
        if (seconds < 10.0) {
            std::ostringstream ss;
            ss << std::fixed << std::setprecision(1) << seconds << "s";
            return ss.str();
        }
        long long s = static_cast<long long>(seconds);
        long long h = s / 3600;
        long long m = (s % 3600) / 60;
        s %= 60;
        std::ostringstream ss;
        if (h > 0) ss << h << "h " << m << "m " << s << "s";
        else if (m > 0) ss << m << "m " << s << "s";
        else ss << s << "s";
        return ss.str();
    }

    void render() {
        size_t done = done_.load();
        double pct = total_ ? (100.0 * static_cast<double>(done) / static_cast<double>(total_)) : 0.0;
        if (pct > 100.0) pct = 100.0;

        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - start_).count();
        double speed = elapsed > 0.0 ? static_cast<double>(bytes_.load()) / elapsed : 0.0;

        const int width = 30;
        int filled = static_cast<int>(pct / 100.0 * width);
        if (filled < 0) filled = 0;
        if (filled > width) filled = width;
        std::string bar(static_cast<size_t>(filled), '#');
        bar.append(static_cast<size_t>(width - filled), '-');

        size_t expected = expectedBytes_.load();

        std::ostringstream ss;
        ss << "\r"
           << CLR(term::CYAN) << label_ << CLR(term::RESET) << " ["
           << CLR(term::GREEN) << bar << CLR(term::RESET) << "] "
           << std::setw(3) << static_cast<int>(pct) << "% "
           << "(" << done << "/" << total_ << ") "
           << formatDuration(elapsed) << " | "
           << formatBytes(static_cast<double>(bytes_.load()));
        if (expected > 0) {
            ss << " / " << formatBytes(static_cast<double>(expected));
        }
        ss << " @ " << formatSpeed(speed);

        std::string line = ss.str();
        const size_t maxLen = 220;
        if (line.size() > maxLen) line = line.substr(0, maxLen - 3) + "...";

        std::cout << line << std::flush;
    }

    std::string label_;
    size_t total_;
    std::atomic<size_t> done_{0};
    std::atomic<size_t> bytes_{0};
    std::atomic<size_t> expectedBytes_{0};
    std::chrono::steady_clock::time_point start_;
    std::chrono::steady_clock::time_point lastRender_;
    std::mutex mtx_;
    bool finished_ = false;
};

} // namespace fivem