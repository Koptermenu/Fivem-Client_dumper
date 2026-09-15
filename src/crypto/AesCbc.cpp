#include "AesCbc.h"

#include <windows.h>
#include <bcrypt.h>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

namespace fivem {

bool aesCbc256DecryptRaw(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv,
                         const std::vector<uint8_t>& data, std::vector<uint8_t>& out) {
    if (key.size() != 32) return false;
    if (data.empty() || data.size() % 16 != 0) return false;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0)
        return false;

    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      const_cast<UCHAR*>(reinterpret_cast<const UCHAR*>(BCRYPT_CHAIN_MODE_CBC)),
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                   const_cast<PUCHAR>(key.data()),
                                   static_cast<ULONG>(key.size()), 0) < 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    std::vector<uint8_t> ivBuf = iv;
    if (ivBuf.size() < 16) ivBuf.resize(16, 0);
    ivBuf.resize(16);

    ULONG result = 0;
    std::vector<uint8_t> tmp(data.size());
    NTSTATUS st = BCryptDecrypt(hKey, const_cast<PUCHAR>(data.data()),
                                static_cast<ULONG>(data.size()), nullptr,
                                ivBuf.data(), 16, tmp.data(),
                                static_cast<ULONG>(tmp.size()), &result, 0);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (st < 0) return false;
    out.assign(tmp.begin(), tmp.begin() + result);
    return true;
}

bool aesCbc256DecryptPkcs7(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv,
                           const std::vector<uint8_t>& data, std::vector<uint8_t>& out) {
    std::vector<uint8_t> padded;
    if (!aesCbc256DecryptRaw(key, iv, data, padded)) return false;

    // Manual PKCS#7 unpad; invalid padding returns raw (matches Python's
    // try/except ValueError: return decrypted fallback)
    if (!padded.empty() && padded.back() >= 1 && padded.back() <= 16) {
        size_t pad = padded.back();
        if (pad <= padded.size()) {
            bool ok = true;
            for (size_t i = padded.size() - pad; i < padded.size(); ++i) {
                if (padded[i] != pad) { ok = false; break; }
            }
            if (ok) {
                out.assign(padded.begin(), padded.end() - pad);
                return true;
            }
        }
    }
    out = std::move(padded);
    return true;
}

} // namespace fivem
