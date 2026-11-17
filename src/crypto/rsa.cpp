// rsa.cpp — RSA-4096-OAEP key wrapping (BCrypt)
#include "rsa.h"
#include <bcrypt.h>
#include <ntstatus.h>
#include <cstring>

#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif

namespace crypto {

bool rsa4096_generate(std::vector<BYTE>& priv_out, std::vector<BYTE>& pub_out) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM,
        NULL, 0) < 0) return false;

    if (BCryptGenerateKeyPair(alg, &key, (ULONG)RSA_KEY_BITS, 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    if (BCryptFinalizeKeyPair(key, 0) < 0) {
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    DWORD priv_len = 0, pub_len = 0;
    BCryptExportKey(key, NULL, BCRYPT_RSAPRIVATE_BLOB,
        NULL, 0, &priv_len, 0);
    BCryptExportKey(key, NULL, BCRYPT_RSAPUBLIC_BLOB,
        NULL, 0, &pub_len, 0);

    priv_out.resize(priv_len);
    pub_out.resize(pub_len);

    NTSTATUS s1 = BCryptExportKey(key, NULL, BCRYPT_RSAPRIVATE_BLOB,
        priv_out.data(), priv_len, &priv_len, 0);
    NTSTATUS s2 = BCryptExportKey(key, NULL, BCRYPT_RSAPUBLIC_BLOB,
        pub_out.data(), pub_len, &pub_len, 0);

    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return s1 >= 0 && s2 >= 0;
}

static bool rsa_open_with_public(const std::vector<BYTE>& pub_key,
                                  BCRYPT_KEY_HANDLE& out,
                                  BCRYPT_ALG_HANDLE& alg) {
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM,
        NULL, 0) < 0) return false;

    if (BCryptImportKeyPair(alg, NULL, BCRYPT_RSAPUBLIC_BLOB,
        &out, (PUCHAR)pub_key.data(), (ULONG)pub_key.size(), 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }
    return true;
}

static bool rsa_open_with_private(const std::vector<BYTE>& priv_key,
                                   BCRYPT_KEY_HANDLE& out,
                                   BCRYPT_ALG_HANDLE& alg) {
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM,
        NULL, 0) < 0) return false;

    if (BCryptImportKeyPair(alg, NULL, BCRYPT_RSAPRIVATE_BLOB,
        &out, (PUCHAR)priv_key.data(), (ULONG)priv_key.size(), 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }
    return true;
}

static const BCRYPT_OAEP_PADDING_INFO OAEP = {
    BCRYPT_SHA256_ALGORITHM, NULL, 0
};

bool rsa4096_encrypt(const std::vector<BYTE>& pub_key,
                     const BYTE* plain, size_t plain_len,
                     std::vector<BYTE>& out) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    if (!rsa_open_with_public(pub_key, key, alg)) return false;

    DWORD out_len = 0;
    NTSTATUS st = BCryptEncrypt(key, (PUCHAR)plain, (ULONG)plain_len,
        (PVOID)&OAEP, NULL, 0, NULL, 0, &out_len, BCRYPT_PAD_OAEP);

    if (st < 0) {
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    out.resize(out_len);
    st = BCryptEncrypt(key, (PUCHAR)plain, (ULONG)plain_len,
        (PVOID)&OAEP, NULL, 0, out.data(), out_len, &out_len, BCRYPT_PAD_OAEP);

    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return st >= 0;
}

bool rsa4096_decrypt(const std::vector<BYTE>& priv_key,
                     const BYTE* cipher, size_t cipher_len,
                     std::vector<BYTE>& out) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    if (!rsa_open_with_private(priv_key, key, alg)) return false;

    DWORD out_len = 0;
    NTSTATUS st = BCryptDecrypt(key, (PUCHAR)cipher, (ULONG)cipher_len,
        (PVOID)&OAEP, NULL, 0, NULL, 0, &out_len, BCRYPT_PAD_OAEP);

    if (st < 0) {
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    out.resize(out_len);
    st = BCryptDecrypt(key, (PUCHAR)cipher, (ULONG)cipher_len,
        (PVOID)&OAEP, NULL, 0, out.data(), out_len, &out_len, BCRYPT_PAD_OAEP);

    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return st >= 0;
}

} // namespace crypto