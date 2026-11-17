// rsa.h — RSA-4096-OAEP key wrapping (BCrypt)
#pragma once

#include <windows.h>
#include <vector>

namespace crypto {

constexpr size_t RSA_KEY_BITS = 4096;
constexpr size_t RSA_BLOB_MAX = 1024;

// Generate RSA-4096 keypair. Returns private key blob (PKCS8) and public (PKCS1).
bool rsa4096_generate(std::vector<BYTE>& priv_out, std::vector<BYTE>& pub_out);

// Encrypt small data (e.g. AES key) with public key. OAEP-SHA256.
bool rsa4096_encrypt(const std::vector<BYTE>& pub_key,
                     const BYTE* plain, size_t plain_len,
                     std::vector<BYTE>& out);

// Decrypt with private key.
bool rsa4096_decrypt(const std::vector<BYTE>& priv_key,
                     const BYTE* cipher, size_t cipher_len,
                     std::vector<BYTE>& out);

} // namespace crypto
