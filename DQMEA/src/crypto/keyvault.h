// keyvault.h — 100+ key management, used-flag tracking
#pragma once

#include <windows.h>
#include <vector>
#include <string>

namespace crypto {

struct KeyEntry {
    BYTE    key[32];        // AES-256 master key
    BYTE    hash[32];       // SHA-256 of user-facing key string
    BYTE    backup[32];     // encrypted backup (XOR with hash for recovery)
    BYTE    used;           // 1 = redeemed
    BYTE    _pad[3];        // alignment
};

static_assert(sizeof(KeyEntry) == 100, "KeyEntry size must be 100 bytes");

struct VaultHeader {
    char    magic[8];       // "DQMEAV1\0"
    DWORD   count;          // number of entries
    BYTE    master_salt[16];// salt for vault encryption
    BYTE    _pad[4];
};

// A vault is a header + KeyEntry[count].
// On disk, it's encrypted with AES-256-CBC using a build-time master key.

class KeyVault {
public:
    // Load vault from disk, decrypt with build-time master key.
    bool load(const std::wstring& path);

    // Save vault to disk (encrypted).
    bool save(const std::wstring& path) const;

    // Validate a user-facing key string. Returns index, or -1.
    // Marks entry as used if valid and unused.
    int redeem(const std::string& user_key);

    // Peek without marking used.
    int find(const std::string& user_key) const;

    // Get AES key at index.
    const BYTE* aes_key(size_t idx) const;

    // Get count.
    size_t count() const { return entries_.size(); }

    // Create a new vault (empty, encrypted).
    bool create(size_t n);

    // Get raw entry.
    const KeyEntry& entry(size_t idx) const { return entries_[idx]; }
    KeyEntry& entry_mut(size_t idx) { return entries_[idx]; }

    // Accessors for backup / used state.
    bool is_used(size_t idx) const { return entries_[idx].used != 0; }
    void mark_used(size_t idx) { entries_[idx].used = 1; }

private:
    std::vector<KeyEntry> entries_;
    BYTE master_salt_[16];
};

} // namespace crypto
