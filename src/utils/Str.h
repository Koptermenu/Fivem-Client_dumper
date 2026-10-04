#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <optional>
namespace fivem {
std::string safeName(const std::string& name);
std::string urlQuote(const std::string& s);
std::string toLower(const std::string& s);
std::string trim(const std::string& s);
bool startsWith(const std::string& s, const std::string& prefix);
bool endsWith(const std::string& s, const std::string& suffix);
bool iequals(const std::string& a, const std::string& b);
std::vector<std::string> split(const std::string& s, char delim);
std::vector<std::string> splitStr(const std::string& s, const std::string& delim);
std::string hexEncode(const std::vector<uint8_t>& data);
std::vector<uint8_t> hexDecode(const std::string& hex);
std::vector<uint8_t> base64Decode(const std::string& in);
std::optional<std::vector<uint8_t>> readFileBytes(const std::string& path);
bool writeFileBytes(const std::string& path, const std::vector<uint8_t>& data);
bool writeTextFile(const std::string& path, const std::string& text);
uint32_t be32(const uint8_t* p);
uint32_t le32(const uint8_t* p);
std::string exeDir();
std::string resolveTool(const std::string& relative);
}
