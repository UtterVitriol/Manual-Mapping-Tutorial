#include "proc.h"

/* Get process ID of process
*  MSDN Tutorial - https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
*/
DWORD GetProcId(const char* procName) {

	DWORD procId = 0;

	/* CreateToolhelp32Snapshot - Takes snapshot of specified processes.
	*  TH32CS_SNAPPROCESS - Include all processes in the system snapshot
	*/
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	// INVALID_HANDLE_VALUE - Error code for CreateToolhelp32Snapshot.
	if (hSnap != INVALID_HANDLE_VALUE) {

		// PROCESSENTRY32 - Describes entry in system process snapshot list (hSnap).
		PROCESSENTRY32 procEntry{};

		// Must set dwSize before calling Process32First.
		procEntry.dwSize = sizeof(procEntry);

		// Process32First - Retrieves information about frist process in system snapshot (hSnap).
		if (Process32First(hSnap, &procEntry)) {
			do {

				/* _wcsicmp - Lexicographical wide string case-insensitive compare.
				*  szExeFile - Name of executable file for the process.
				*/
				if (!_stricmp(procEntry.szExeFile, procName)) {

					// the32ProcessID - Process ID of process entry.
					procId = procEntry.th32ProcessID;
					break;
				}

				// Process32Next - Retrieves information about next process in system snapshot (hSnap).
			} while (Process32Next(hSnap, &procEntry));
		}
	}

	CloseHandle(hSnap);
	return procId;
}

uintptr_t GetModuleBaseAddress(DWORD procId, const char* modName) {

	uintptr_t modBaseAddr = 0;

	/* THE32CS_SNAPMODULE - Include 64-bit modules
	/* THE32CS_SNAPMODULE32 - Include 32-bit modules
	*/
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE, procId);

	// INVALID_HANDLE_VALUE - Error code for CreateToolhelp32Snapshot.
	if (hSnap != INVALID_HANDLE_VALUE) {

		// MODULEENTRY32 - Describes entry from list of modules (hSnap).
		MODULEENTRY32 modEntry{};

		// Must set dwSize before calling Module32First
		modEntry.dwSize = sizeof(modEntry);

		// Module32First - Retrieves information from the first module in snapshot.
		if (Module32First(hSnap, &modEntry)) {
			do {

				// szModule - Module name.
				if (!_stricmp(modEntry.szModule, modName)) {

					modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
					break;
				}

				// Module32Next - Retrieves information from the next module in snapshot.
			} while (Module32Next(hSnap, &modEntry));
		}
	}

	CloseHandle(hSnap);
	return modBaseAddr;
}

