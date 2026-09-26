#pragma once

#include <string>

namespace fivem {

// Ensures the embedded payload (Unpacker + deps + unluac jar) is extracted to
// %LOCALAPPDATA%\FiveMDumper\payload. Verifies every file's size + SHA256 each
// process start, so an antivirus rollback is repaired transparently.
// Returns true when the payload is ready. errOut carries the failure reason.
bool ensurePayload(std::string& errOut);

// UTF-8 payload root (backslashes); empty until ensurePayload succeeded.
std::string payloadRoot();

} // namespace fivem
