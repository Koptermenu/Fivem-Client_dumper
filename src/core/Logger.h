#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace fivem {

enum class LogLevel {
    INFO,
    WARNING,
    ERROR,
    SUCCESS
};

class Logger {
public:
    static Logger& instance() {
        static Logger logger;
        return logger;
    }

    void log(const std::string& message, LogLevel level = LogLevel::INFO);
    void setLogFile(const std::string& filename);

private:
    Logger();
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    std::ofstream logFile_;
    std::mutex mutex_;
    std::string timestamp();
    std::string levelToString(LogLevel level);
};

// Convenience macro
#define LOG(msg, level) fivem::Logger::instance().log(msg, level)

} // namespace fivem