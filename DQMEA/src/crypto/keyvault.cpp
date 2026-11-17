// keyvault.cpp — 100+ key management, used-flag tracking
#include "keyvault.h"
#include "aes.h"
#include "hash.h"
#include <fstream>

namespace crypto {

// Build-time master key for vault at-rest encryption.
// REPLACE with your own 32-byte value before build.
static const BYTE VAULT_MASTER_KEY[32] = {
    0x4D, 0x45, 0x41, 0x4D, 0x41, 0x53, 0x54, 0x45,
    0x52, 0x4B, 0x45, 0x59, 0x31, 0x32, 0x33, 0x34,
    0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43,
    0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
};

bool KeyVault::load(const std::wstring& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;

    std::vector<BYTE> enc((std::istreambuf_iterator<char>(f)),
                           std::istreambuf_iterator<char>());
    if (enc.size() < AES_IV_LEN + AES_BLOCK) return false;

    std::vector<BYTE> plain;
    if (!aes256_cbc_decrypt(VAULT_MASTER_KEY, enc.data(), enc.size(), plain))
        return false;

    if (plain.size() < sizeof(VaultHeader)) return false;

    VaultHeader hdr;
    memcpy(&hdr, plain.data(), sizeof(hdr));
    if (memcmp(hdr.magic, "DQMEAV1", 7) != 0) return false;

    size_t expected = sizeof(VaultHeader) + sizeof(KeyEntry) * hdr.count;
    if (plain.size() != expected) return false;

    entries_.resize(hdr.count);
    memcpy(entries_.data(), plain.data() + sizeof(VaultHeader),
           sizeof(KeyEntry) * hdr.count);
    memcpy(master_salt_, hdr.master_salt, 16);
    return true;
}

bool KeyVault::save(const std::wstring& path) const {
    VaultHeader hdr;
    memcpy(hdr.magic, "DQMEAV1", 7);
    hdr.magic[7] = 0;
    hdr.count = (DWORD)entries_.size();
    memcpy(hdr.master_salt, master_salt_, 16);
    memset(hdr._pad, 0, sizeof(hdr._pad));

    std::vector<BYTE> plain(sizeof(hdr) + sizeof(KeyEntry) * entries_.size());
    memcpy(plain.data(), &hdr, sizeof(hdr));
    memcpy(plain.data() + sizeof(hdr), entries_.data(),
           sizeof(KeyEntry) * entries_.size());

    std::vector<BYTE> enc;
    if (!aes256_cbc_encrypt(VAULT_MASTER_KEY, plain.data(), plain.size(),
                            NULL, enc))
        return false;

    std::ofstream f(path, std::ios::binary);
    f.write((const char*)enc.data(), enc.size());
    return f.good();
}

int KeyVault::find(const std::string& user_key) const {
    BYTE hash[32];
    if (!sha256_string(user_key, hash)) return -1;

    for (size_t i = 0; i < entries_.size(); i++) {
        if (ct_compare(entries_[i].hash, hash, 32)) return (int)i;
    }
    return -1;
}

int KeyVault::redeem(const std::string& user_key) {
    int idx = find(user_key);
    if (idx < 0) return -1;
    if (entries_[idx].used) return -2;  // already used
    entries_[idx].used = 1;
    return idx;
}

const BYTE* KeyVault::aes_key(size_t idx) const {
    if (idx >= entries_.size()) return nullptr;
    return entries_[idx].key;
}

bool KeyVault::create(size_t n) {
    entries_.resize(n);
    if (!random_bytes(master_salt_, 16)) return false;

    for (size_t i = 0; i < n; i++) {
        if (!random_bytes(entries_[i].key, 32)) return false;
        if (!random_bytes(entries_[i].backup, 32)) return false;
        // hash of key string generated elsewhere; placeholder 0
        memset(entries_[i].hash, 0, 32);
        entries_[i].used = 0;
        memset(entries_[i]._pad, 0, 3);
    }
    return true;
}

} // namespace crypto
