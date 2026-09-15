#include "Logger.h"
#include "../utils/Term.h"
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

    std::string prefix = "[" + timestamp() + "] [" + levelToString(level) + "] ";
    std::string logLine = prefix + message;

    // Console output. Warnings go to the file only; INFO shows with a dim
    // timestamp prefix; ERROR/SUCCESS are colored (no-op when colors are off).
    if (level == LogLevel::WARNING) {
        // file only
    } else if (level == LogLevel::ERROR) {
        std::cout << CLR(term::RED) << logLine << CLR(term::RESET) << "\n";
    } else if (level == LogLevel::SUCCESS) {
        std::cout << CLR(term::GREEN) << logLine << CLR(term::RESET) << "\n";
    } else {
        std::cout << CLR(term::DIM) << prefix << CLR(term::RESET) << message << "\n";
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