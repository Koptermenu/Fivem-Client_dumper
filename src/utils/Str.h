#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace fivem {

// Sanitize a name for use as a directory (replaces <>:"/\|?* with _)
std::string safeName(const std::string& name);

// URL percent-encoding, matching Python's urllib.parse.quote (safe = '/')
std::string urlQuote(const std::string& s);

// Lowercase copy
std::string toLower(const std::string& s);

// Trim whitespace
std::string trim(const std::string& s);

// Check prefix/suffix
bool startsWith(const std::string& s, const std::string& prefix);
bool endsWith(const std::string& s, const std::string& suffix);
bool iequals(const std::string& a, const std::string& b);

// Split by delimiter
std::vector<std::string> split(const std::string& s, char delim);

// Split by string
std::vector<std::string> splitStr(const std::string& s, const std::string& delim);

// Lowercase hex string from bytes
std::string hexEncode(const std::vector<uint8_t>& data);

// Bytes from hex string
std::vector<uint8_t> hexDecode(const std::string& hex);

// Base64 decode (accepts standard + url-safe alphabets; pads if needed)
std::vector<uint8_t> base64Decode(const std::string& in);

// Read whole file as bytes
std::optional<std::vector<uint8_t>> readFileBytes(const std::string& path);

// Write bytes to file (creating parent dirs)
bool writeFileBytes(const std::string& path, const std::vector<uint8_t>& data);

// Write text to file (creating parent dirs)
bool writeTextFile(const std::string& path, const std::string& text);

// Little/big endian helpers
uint32_t be32(const uint8_t* p);
uint32_t le32(const uint8_t* p);

// Directory of the running executable (backslashes), "" if unavailable.
std::string exeDir();

// Resolve a project-relative tool path (e.g. "Bin/Unpacker.exe") independent of
// the current working directory: checks cwd, then the exe dir and its parents
// (covers running from build/Release). Returns rel unchanged if nothing exists.
std::string resolveTool(const std::string& relative);

} // namespace fivem
