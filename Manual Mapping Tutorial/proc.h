#pragma once

#include <vector>
#include <Windows.h>
#include <TlHelp32.h>

DWORD GetProcId(const char* procName);

uintptr_t GetModuleBaseAddress(DWORD procId, const char* modName);

