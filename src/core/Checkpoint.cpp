#include "Checkpoint.h"
#include "Logger.h"
#include <fstream>
#include <sstream>

namespace fivem {

// Simple JSON parser (no external dependencies for minimalism)
namespace {
    std::string trim(const std::string& s) {
        size_t start = s.find_first_not_of(" \t\n\r");
        if (start == std::string::npos) return "";
        size_t end = s.find_last_not_of(" \t\n\r");
        return s.substr(start, end - start + 1);
    }

    std::vector<std::string> parseStringArray(const std::string& json) {
        std::vector<std::string> result;
        size_t start = json.find('[');
        if (start == std::string::npos) return result;

        size_t end = json.find(']', start);
        if (end == std::string::npos) return result;

        std::string array = json.substr(start + 1, end - start - 1);
        std::stringstream ss(array);
        std::string item;

        while (std::getline(ss, item, ',')) {
            size_t quoteStart = item.find('"');
            size_t quoteEnd = item.find('"', quoteStart + 1);
            if (quoteStart != std::string::npos && quoteEnd != std::string::npos) {
                std::string value = item.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
                result.push_back(value);
            }
        }
        return result;
    }

    std::string extractString(const std::string& json, const std::string& key) {
        std::string searchKey = "\"" + key + "\"";
        size_t pos = json.find(searchKey);
        if (pos == std::string::npos) return "";

        size_t colon = json.find(':', pos);
        if (colon == std::string::npos) return "";

        size_t quote1 = json.find('"', colon);
        if (quote1 == std::string::npos) return "";

        size_t quote2 = json.find('"', quote1 + 1);
        if (quote2 == std::string::npos) return "";

        return json.substr(quote1 + 1, quote2 - quote1 - 1);
    }

    bool stringContains(const std::string& haystack, const std::string& needle) {
        return haystack.find(needle) != std::string::npos;
    }
}

bool Checkpoint::load(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    file.close();

    completed_resources = parseStringArray(content);
    current_resource = extractString(content, "current_resource");
    server_ip = extractString(content, "server_ip");

    LOG("Loaded checkpoint from " + filename, LogLevel::INFO);
    return true;
}

bool Checkpoint::save(const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        LOG("Failed to open checkpoint file for writing: " + filename, LogLevel::ERROR);
        return false;
    }

    file << "{\n";
    file << "  \"completed_resources\": [";
    for (size_t i = 0; i < completed_resources.size(); ++i) {
        if (i > 0) file << ", ";
        file << "\"" << completed_resources[i] << "\"";
    }
    file << "],\n";

    if (current_resource) {
        file << "  \"current_resource\": \"" << *current_resource << "\",\n";
    } else {
        file << "  \"current_resource\": null,\n";
    }

    if (server_ip) {
        file << "  \"server_ip\": \"" << *server_ip << "\"\n";
    } else {
        file << "  \"server_ip\": null\n";
    }

    file << "}\n";
    file.close();

    LOG("Saved checkpoint to " + filename, LogLevel::INFO);
    return true;
}

void Checkpoint::clear(const std::string& filename) {
    std::ifstream file(filename);
    if (file.is_open()) {
        file.close();
        std::remove(filename.c_str());
        LOG("Cleared checkpoint file", LogLevel::INFO);
    }
}

} // namespace fivem