// hash.cpp — SHA-256, HMAC-SHA256 wrappers (BCrypt)
#include "hash.h"
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

namespace crypto {

bool sha256(const BYTE* data, size_t len, BYTE out[32]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    DWORD obj_len = 0, result = 0, hash_len = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
        NULL, 0) < 0) return false;

    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&obj_len, sizeof(DWORD), &result, 0);
    BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
        (PUCHAR)&hash_len, sizeof(DWORD), &result, 0);

    std::vector<BYTE> obj(obj_len);
    if (BCryptCreateHash(alg, &hash, obj.data(), obj_len, NULL, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    BCryptHashData(hash, (PUCHAR)data, (ULONG)len, 0);
    BCryptFinishHash(hash, out, hash_len, 0);

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return hash_len == 32;
}

bool sha256_string(const std::string& in, BYTE out[32]) {
    return sha256((const BYTE*)in.data(), in.size(), out);
}

bool hmac_sha256(const BYTE* key, size_t key_len,
                 const BYTE* data, size_t data_len,
                 BYTE out[32]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    DWORD obj_len = 0, result = 0, hash_len = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
        NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0) return false;

    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&obj_len, sizeof(DWORD), &result, 0);
    BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
        (PUCHAR)&hash_len, sizeof(DWORD), &result, 0);

    std::vector<BYTE> obj(obj_len);
    if (BCryptCreateHash(alg, &hash, obj.data(), obj_len,
        (PUCHAR)key, (ULONG)key_len, 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    BCryptHashData(hash, (PUCHAR)data, (ULONG)data_len, 0);
    BCryptFinishHash(hash, out, hash_len, 0);

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return hash_len == 32;
}

bool ct_compare(const BYTE* a, const BYTE* b, size_t len) {
    volatile BYTE diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

bool random_bytes(BYTE* out, size_t len) {
    return BCryptGenRandom(NULL, out, (ULONG)len,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
}

static const char* HEX = "0123456789abcdef";

std::string hex_encode(const BYTE* data, size_t len) {
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; i++) {
        out[i*2]   = HEX[data[i] >> 4];
        out[i*2+1] = HEX[data[i] & 0x0F];
    }
    return out;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool hex_decode(const std::string& hex, std::vector<BYTE>& out) {
    if (hex.size() % 2 != 0) return false;
    out.resize(hex.size() / 2);
    for (size_t i = 0; i < out.size(); i++) {
        int hi = hex_nibble(hex[i*2]);
        int lo = hex_nibble(hex[i*2+1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (BYTE)((hi << 4) | lo);
    }
    return true;
}

} // namespace crypto
