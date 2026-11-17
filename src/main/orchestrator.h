// orchestrator.h — Main phase sequencing
#pragma once

#include <windows.h>
#include <atomic>

namespace orchestrator {

// Run the full DQMEA attack lifecycle.
int run();

// Check for abort signal (used by watchdog / UI).
extern std::atomic<bool> g_abort;

} // namespace orchestrator
