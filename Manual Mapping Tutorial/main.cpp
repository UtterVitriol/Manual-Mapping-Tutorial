#include "Injection.h"
#include "proc.h"

#ifdef _WIN64
const char szDllFile[] = "C:\\Users\\uttervitriol\\source\\repos\\AC_Internal_Hack_1_Follow_Along\\Debug\\AC_Internal_Hack_1.dll";
const char szProc[] = "ac_client.exe";
#else
const char szDllFile[] = "C:\\Users\\uttervitriol\\source\\repos\\AC_Internal_Hack_1_Follow_Along\\Debug\\AC_Internal_Hack_1.dll";
const char szProc[] = "ac_client.exe";
#endif

bool IsCorrectTargetArchitecture(HANDLE hProc)
{
	BOOL bTarget = FALSE;
	if (!IsWow64Process(hProc, &bTarget))
	{
		printf("Can't confirm target process architecture: 0x%X\n", GetLastError());
		return false;
	}

	BOOL bHost = FALSE;
	IsWow64Process(GetCurrentProcess(), &bHost);

	return (bTarget == bHost);
}

int main()
{
	DWORD dwPID = 0;

	dwPID = GetProcId(szProc);

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (!hProc)
	{
		DWORD Err = GetLastError();
		printf("OpenProcess failed: 0x%X\n", Err);
		system("PAUSE");
		return 0;
	}

	if (!IsCorrectTargetArchitecture(hProc))
	{
		printf("Invalid target process.\n");
		CloseHandle(hProc);
		system("PAUSE");
		return 0;
	}
	
	if (!ManualMap(hProc, szDllFile))
	{
		CloseHandle(hProc);
		printf("Something went wrong FeelsBadMan\n");
		system("PAUSE");
		return 0;
	}

	CloseHandle(hProc);
		
	return 0;
}