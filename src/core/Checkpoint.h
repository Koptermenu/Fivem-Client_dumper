#pragma once

#include <string>
#include <vector>
#include <optional>

namespace fivem {

struct Checkpoint {
    std::vector<std::string> completed_resources;
    std::optional<std::string> current_resource;
    std::optional<std::string> server_ip;

    bool load(const std::string& filename = "checkpoint.json");
    bool save(const std::string& filename = "checkpoint.json");
    void clear(const std::string& filename = "checkpoint.json");
};

} // namespace fivem