// aes.h — AES-256-CBC wrapper (BCrypt)
#pragma once

#include <windows.h>
#include <vector>

namespace crypto {

constexpr size_t AES_KEY_LEN  = 32;
constexpr size_t AES_IV_LEN   = 16;
constexpr size_t AES_BLOCK    = 16;

// Encrypt plaintext with AES-256-CBC. Output: [IV (16)] [ciphertext]
// Caller must generate IV or pass nullptr for random.
bool aes256_cbc_encrypt(const BYTE key[AES_KEY_LEN],
                        const BYTE* plain, size_t plain_len,
                        const BYTE* iv_or_null,
                        std::vector<BYTE>& out);

// Decrypt input (format: [IV (16)] [ciphertext]).
bool aes256_cbc_decrypt(const BYTE key[AES_KEY_LEN],
                        const BYTE* input, size_t input_len,
                        std::vector<BYTE>& out);

} // namespace crypto
