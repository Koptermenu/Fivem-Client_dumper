#pragma once
#include <string>

namespace fivem {

// Repairs the vertex buffers of the model files that come out of FXAP decryption.
//
// Decryption restores the resource bytes, but a .ydr/.ydd/.yft that was encrypted with
// its vertex data still encrypted or truncated does not load in the game. The repair is
// done by an external .NET tool, so this only drives it: the fixable files are copied to
// a scratch directory, the tool rewrites them there, and the results replace the
// originals. The originals are never handed to the tool directly, so a crash or a
// half-written output cannot leave the dump in a worse state than before.
//
// One asymmetry with the reference JavaScript driver is deliberate. It kept a pristine
// full copy of the output tree and always copied the result back, because it could fall
// back on that copy. A dumper deletes Temp, TempCompiled and Unpacked once Output exists
// (see main.cpp), so there is nothing to fall back on here: the result is only copied
// back after the tool has exited cleanly, and each file is staged through a temporary name
// so an interrupted write cannot truncate a good model.
struct VertexFixStats {
    bool ran = false;
    bool ok = false;
    int scanned = 0;
    int repaired = 0;
    int failed = 0;
    int files = 0;
    int written = 0;
    double seconds = 0.0;
    std::string message;
};

VertexFixStats runVertexFix(const std::string& root);

}  // namespace fivem