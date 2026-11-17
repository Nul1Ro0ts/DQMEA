// dqmea.cpp — Entry point (ANSI WinMain — no -municode needed)
#include <windows.h>
#include "orchestrator.h"
#include "util/filesystem.h"

#define MUTEX_NAME L"Global\\DqmeaMutex_7F3A9B2C"

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nShow;

    // 1. Single-instance check
    HANDLE hMutex = CreateMutexW(NULL, TRUE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    // 2. Run orchestrator
    orchestrator::run();

    // 3. Cleanup
    if (hMutex) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    }
    return 0;
}