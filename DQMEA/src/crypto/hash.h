// hash.h — SHA-256, HMAC-SHA256 wrappers (BCrypt)
#pragma once

#include <windows.h>
#include <vector>
#include <string>

namespace crypto {

// SHA-256 of input. Returns 32-byte digest.
bool sha256(const BYTE* data, size_t len, BYTE out[32]);

// SHA-256 of string.
bool sha256_string(const std::string& in, BYTE out[32]);

// HMAC-SHA256.
bool hmac_sha256(const BYTE* key, size_t key_len,
                 const BYTE* data, size_t data_len,
                 BYTE out[32]);

// Constant-time comparison.
bool ct_compare(const BYTE* a, const BYTE* b, size_t len);

// Random bytes from BCryptGenRandom.
bool random_bytes(BYTE* out, size_t len);

// Hex encode/decode.
std::string hex_encode(const BYTE* data, size_t len);
bool hex_decode(const std::string& hex, std::vector<BYTE>& out);

} // namespace crypto
