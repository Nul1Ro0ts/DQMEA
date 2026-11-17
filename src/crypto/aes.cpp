// aes.cpp — AES-256-CBC wrapper (BCrypt)
#include "aes.h"
#include "hash.h"
#include <bcrypt.h>
#include <cstring>

#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif

namespace crypto {

static bool aes_crypt(const BYTE key[AES_KEY_LEN],
                      const BYTE iv[AES_IV_LEN],
                      const BYTE* input, size_t input_len,
                      std::vector<BYTE>& out,
                      bool encrypt) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key_h = NULL;
    DWORD obj_len = 0, block_len = 0, result = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM,
        NULL, 0) < 0) return false;

    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC), 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&obj_len, sizeof(DWORD), &result, 0);
    BCryptGetProperty(alg, BCRYPT_BLOCK_LENGTH,
        (PUCHAR)&block_len, sizeof(DWORD), &result, 0);

    std::vector<BYTE> obj(obj_len);
    std::vector<BYTE> iv_copy(iv, iv + AES_IV_LEN);

    if (BCryptGenerateSymmetricKey(alg, &key_h, obj.data(), obj_len,
        (PUCHAR)key, AES_KEY_LEN, 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    out.resize(input_len + block_len);
    ULONG out_len = 0;

    NTSTATUS st;
    if (encrypt) {
        st = BCryptEncrypt(key_h, (PUCHAR)input, (ULONG)input_len,
            NULL, iv_copy.data(), AES_IV_LEN,
            out.data(), (ULONG)out.size(), &out_len, BCRYPT_BLOCK_PADDING);
    } else {
        st = BCryptDecrypt(key_h, (PUCHAR)input, (ULONG)input_len,
            NULL, iv_copy.data(), AES_IV_LEN,
            out.data(), (ULONG)out.size(), &out_len, BCRYPT_BLOCK_PADDING);
    }

    BCryptDestroyKey(key_h);
    BCryptCloseAlgorithmProvider(alg, 0);

    if (st < 0) return false;
    out.resize(out_len);
    return true;
}

bool aes256_cbc_encrypt(const BYTE key[AES_KEY_LEN],
                        const BYTE* plain, size_t plain_len,
                        const BYTE* iv_or_null,
                        std::vector<BYTE>& out) {
    BYTE iv[AES_IV_LEN];
    if (iv_or_null) {
        memcpy(iv, iv_or_null, AES_IV_LEN);
    } else {
        if (!random_bytes(iv, AES_IV_LEN)) return false;
    }

    std::vector<BYTE> cipher;
    if (!aes_crypt(key, iv, plain, plain_len, cipher, true))
        return false;

    out.resize(AES_IV_LEN + cipher.size());
    memcpy(out.data(), iv, AES_IV_LEN);
    memcpy(out.data() + AES_IV_LEN, cipher.data(), cipher.size());
    return true;
}

bool aes256_cbc_decrypt(const BYTE key[AES_KEY_LEN],
                        const BYTE* input, size_t input_len,
                        std::vector<BYTE>& out) {
    if (input_len < AES_IV_LEN + AES_BLOCK) return false;

    BYTE iv[AES_IV_LEN];
    memcpy(iv, input, AES_IV_LEN);

    const BYTE* cipher = input + AES_IV_LEN;
    size_t cipher_len = input_len - AES_IV_LEN;

    return aes_crypt(key, iv, cipher, cipher_len, out, false);
}

} // namespace crypto