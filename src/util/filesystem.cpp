// filesystem.cpp — Path and file operation helpers
#include "filesystem.h"
#include <shlwapi.h>

#ifdef _MSC_VER
#pragma comment(lib, "shlwapi.lib")
#endif

namespace util {

bool read_file(const std::wstring& path, std::vector<BYTE>& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size) || size.QuadPart > (1LL << 31)) {
        CloseHandle(h);
        return false;
    }

    out.resize((size_t)size.QuadPart);
    DWORD read = 0;
    BOOL ok = ReadFile(h, out.data(), (DWORD)out.size(), &read, NULL);
    CloseHandle(h);
    return ok && read == (DWORD)out.size();
}

bool write_file(const std::wstring& path, const std::vector<BYTE>& data) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;

    DWORD written = 0;
    BOOL ok = WriteFile(h, data.data(), (DWORD)data.size(), &written, NULL);
    CloseHandle(h);
    return ok && written == (DWORD)data.size();
}

bool append_file(const std::wstring& path, const std::vector<BYTE>& data) {
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, 0, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;

    DWORD written = 0;
    BOOL ok = WriteFile(h, data.data(), (DWORD)data.size(), &written, NULL);
    CloseHandle(h);
    return ok && written == (DWORD)data.size();
}

uint64_t file_size(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad))
        return 0;
    return ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
}

bool file_exists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES;
}

bool delete_file(const std::wstring& path) {
    return DeleteFileW(path.c_str()) != 0;
}

bool create_directories(const std::wstring& path) {
    if (path.empty()) return false;
    if (file_exists(path)) return true;

    std::wstring parent = get_directory(path);
    if (!parent.empty() && parent != path) {
        create_directories(parent);
    }

    return CreateDirectoryW(path.c_str(), NULL) != 0 ||
           GetLastError() == ERROR_ALREADY_EXISTS;
}

std::wstring get_extension(const std::wstring& path) {
    const wchar_t* ext = PathFindExtensionW(path.c_str());
    return ext ? std::wstring(ext) : std::wstring();
}

std::wstring get_directory(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return L"";
    return path.substr(0, pos);
}

std::wstring join_path(const std::wstring& a, const std::wstring& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    wchar_t last = a.back();
    if (last == L'\\' || last == L'/') return a + b;
    return a + L"\\" + b;
}

std::vector<std::wstring> get_drive_roots(DWORD drive_types) {
    std::vector<std::wstring> drives;
    wchar_t buffer[512] = {0};
    DWORD len = GetLogicalDriveStringsW(512, buffer);
    if (len == 0) return drives;

    for (wchar_t* p = buffer; *p; p += wcslen(p) + 1) {
        DWORD type = GetDriveTypeW(p);
        if (type & drive_types) {
            drives.emplace_back(p);
        }
    }
    return drives;
}

bool enable_privileges() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    const wchar_t* privs[] = {
        SE_DEBUG_NAME,
        SE_BACKUP_NAME,
        SE_RESTORE_NAME,
        SE_TAKE_OWNERSHIP_NAME,
        SE_SHUTDOWN_NAME,
    };

    bool all_ok = true;
    for (auto name : privs) {
        LUID luid;
        if (!LookupPrivilegeValueW(NULL, name, &luid)) {
            all_ok = false;
            continue;
        }
        TOKEN_PRIVILEGES tp;
        ZeroMemory(&tp, sizeof(tp));
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    }

    CloseHandle(token);
    return all_ok;
}

} // namespace util