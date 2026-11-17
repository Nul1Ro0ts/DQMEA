#pragma once 

#include <windows.h>
#include <string>
#include <vector>

namespace util {

bool read_file(const std::wstring& path, std::vector<BYTE>& out);

bool write_file(const std::wstring& path, const std::vector<BYTE>& data);

bool append_file(const std::wstring& path, const std::vector<BYTE>& data);

uint64_t file_size(const std::wstring& path);

bool file_exists(const std::wstring& path);

bool delete_file(const std::wstring& path);

bool create_directories(const std::wstring& path);

std::wstring get_extention(const std::wstring& path);

std::wstring get_directory(const std::wstring& path);

std::wstring join_path(const std::wstring& a, const std::wstring& b);

std::vector<std::wstring> get_drive_roots(DWORD drive_types);

bool enable_privilages();
}