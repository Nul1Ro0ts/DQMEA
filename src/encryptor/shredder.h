// shredder.h — Secure file deletion (DOD 5220.22-M style)
#pragma once

#include <windows.h>
#include <string>

namespace encryptor {

// Overwrite file with random data N passes, then delete.
// Returns true on success.
bool shred_file(const std::wstring& path, int passes = 3);

} // namespace encryptor
