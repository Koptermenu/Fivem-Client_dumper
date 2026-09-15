#include "Logger.h"
#include <iostream>
#include <filesystem>

namespace fivem {

Logger::Logger() {
    setLogFile("dumper.log");
}

Logger::~Logger() {
    if (logFile_.is_open()) {
        logFile_.close();
    }
}

std::string Logger::timestamp() {
    auto now = std::time(nullptr);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string Logger::levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::INFO:    return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR:   return "ERROR";
        case LogLevel::SUCCESS: return "SUCCESS";
        default:                return "UNKNOWN";
    }
}

void Logger::log(const std::string& message, LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string logLine = "[" + timestamp() + "] [" + levelToString(level) + "] " + message;

    // Console output (WARNING and above only, INFO and SUCCESS too verbose)
    if (level == LogLevel::WARNING) {
        // Warnings go only to file, not console
    } else if (level == LogLevel::ERROR) {
        std::cout << "\033[31m" << logLine << "\033[0m\n";
    } else if (level == LogLevel::SUCCESS) {
        std::cout << "\033[32m" << logLine << "\033[0m\n";
    } else {
        std::cout << logLine << "\n";
    }

    // Always write to file
    if (logFile_.is_open()) {
        logFile_ << logLine << "\n";
        logFile_.flush();
    }
}

void Logger::setLogFile(const std::string& filename) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (logFile_.is_open()) {
        logFile_.close();
    }
    logFile_.open(filename, std::ios::app);
}

} // namespace fivem