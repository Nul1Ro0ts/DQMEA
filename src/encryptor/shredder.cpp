// shredder.cpp — Secure file deletion
#include "shredder.h"
#include "crypto/hash.h"
#include <vector>

namespace encryptor {

bool shred_file(const std::wstring& path, int passes) {
    // Must have write access
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size)) {
        CloseHandle(h);
        return false;
    }

    if (size.QuadPart == 0) {
        CloseHandle(h);
        DeleteFileW(path.c_str());
        return true;
    }

    const DWORD CHUNK = 1 << 20; // 1MB
    std::vector<BYTE> buf(CHUNK);

    for (int p = 0; p < passes; p++) {
        SetFilePointer(h, 0, NULL, FILE_BEGIN);
        LONGLONG remaining = size.QuadPart;

        while (remaining > 0) {
            DWORD to_write = (DWORD)((remaining > CHUNK) ? CHUNK : remaining);
            if (!crypto::random_bytes(buf.data(), to_write)) {
                CloseHandle(h);
                return false;
            }
            DWORD written = 0;
            if (!WriteFile(h, buf.data(), to_write, &written, NULL) ||
                written != to_write) {
                CloseHandle(h);
                return false;
            }
            remaining -= written;
        }
        FlushFileBuffers(h);
    }

    // Truncate to zero length before delete (removes recoverable data)
    SetFilePointer(h, 0, NULL, FILE_BEGIN);
    SetEndOfFile(h);
    CloseHandle(h);

    // Rename to random before delete (defeats some recovery tools)
    wchar_t tmp_name[MAX_PATH];
    wchar_t tmp_dir[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp_dir);
    GetTempFileNameW(tmp_dir, L"dqm", 0, tmp_name);
    MoveFileExW(path.c_str(), tmp_name, MOVEFILE_REPLACE_EXISTING);

    DeleteFileW(tmp_name);
    return true;
}

} // namespace encryptor
