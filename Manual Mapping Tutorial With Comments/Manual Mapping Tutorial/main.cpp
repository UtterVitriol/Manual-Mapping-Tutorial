#include "Injection.h"
//Build this manual mapping injector in Release
//Debug mode won't work since the manual mapping method only covers the really basic stuff. 
//Here complete PE loaders can be found:
//https://github.com/DarthTon/Blackbone/tree/master/src/BlackBoneDrv
//https://github.com/Akaion/Bleak
//https://github.com/Dewera/Lunar

/* 
*The author Broihon wrote this code with compatibility for x86 and x64 programms
#ifdef _WIN64 

//This condition won't work if you build project in x86 version because _WIN64 is defined only in x64 configuration
//In x64 version of the injector the code will use only that condition

const char szDllFile[] = "C:\\Users\\konra\\Desktop\\Test Dll x64.dll";
const char szProc[] = "Test Console x64.exe";
#else

//This condition for x86 version of the injector
//In x86 version of the injector the code will use only that condition
//because _WIN64 symbol doesn't defined in x86 version

const char szDllFile[] = "C:\\Users\\konra\\Desktop\\Test Dll x86.dll";
const char szProc[] = "Test Console x86.exe";
#endif
*/

//We need to set our target process name and Dll path manually for every game and therefore two strings is enougth here
//Just don't forget that injector, DLL and target process should have same architecture
const char szDllFile[] = "C:\\Dev\\Dummy.dll";
const char szProc[] = "csgo.exe";

bool IsCorrectTargetArchitecture(HANDLE hProc) // function for catch an error with architecture
{
	BOOL bTarget = FALSE;
	if (!IsWow64Process(hProc, &bTarget)) //set TRUE to bTarget if hProc is x86 running under x64 system, otherwise False. IsWow64Process returns 0 if the function fails
	{
		printf("Can't confirm target process architecture: 0x%X\n", GetLastError());
		return false;
	}

	BOOL bHost = FALSE;
	IsWow64Process(GetCurrentProcess(), &bHost); //set TRUE to bHost if CurrentProcess is x86 running under x64 system, otherwise False

	return (bTarget == bHost);
}

int main()
{
	PROCESSENTRY32 PE32{ 0 }; //tlhelp32.h structure that contain a process information
	/*
	typedef struct tagPROCESSENTRY32 {
		DWORD   dwSize;					- The size of the structure, in bytes. 
											Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32). 
											If you do not initialize dwSize, Process32First fails.
											https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32
		DWORD   cntUsage;
		DWORD   th32ProcessID;          // this process
		ULONG_PTR th32DefaultHeapID;
		DWORD   th32ModuleID;           // associated exe
		DWORD   cntThreads;
		DWORD   th32ParentProcessID;    // this process's parent process
		LONG    pcPriClassBase;         // Base priority of process's threads
		DWORD   dwFlags;
		CHAR    szExeFile[MAX_PATH];    // The name of the executable file for the process. 
	} PROCESSENTRY32;
	*/
	PE32.dwSize = sizeof(PE32); 

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //TH32CS_SNAPPROCESS = 0x00000002 Includes all processes in the system to the snapshot hSnap. 
	//Process32First and Process32Next can enumerate the processes in hSnap
	/*
	* About HANDLE:
		An application cannot directly access object data or the system resource that an object represents. 
		Instead, an application must obtain an object handle, which it can use to examine or modify the system resource. 
		Each handle has an entry in an internally maintained table. These entries contain the addresses of the resources and the means to identify the resource type.
	* About CreateToolhelp32Snapshot
		CreateToolhelp32Snapshot helps to enumerate all processes/modules/threads that processor run. It's impossible without snapshot 
		(which kinda screenshot or freeze all processes at the time in the memory) because processes can run and end every second and without 
		"freezing time" (snapshot), enumerating can return many errors.
	*/
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		DWORD Err = GetLastError();
		printf("CreateToolhelp32Snapshot failed: 0x%X\n", Err);
		system("PAUSE");
		return 0;
	}	
	DWORD PID = 0;
	BOOL bRet = Process32First(hSnap, &PE32); //Process32First and Process32Next return True if they found a process which they put to the &PE32 address
	while (bRet)
	{
		if (!strcmp(szProc, PE32.szExeFile)) // PE32.szExeFile is the name of the executable file for the process (It doesn't contain path)
		{
			PID = PE32.th32ProcessID;
			break;
		}
		bRet = Process32Next(hSnap, &PE32);
	}

	CloseHandle(hSnap); //after getting process ID (PID) CreateToolhelp32Snapshot doesn't needed anymore. We should close the HANDLE.

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID); 
	// Second parameter in OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID) means that the processes which created by this process will not inherit this handle
	
	if (!hProc) //If OpenProcess fails it returns NULL. Check for OpenProcess Error
	{
		DWORD Err = GetLastError();
		printf("OpenProcess failed: 0x%X\n", Err);
		system("PAUSE");
		return 0;
	}
	//IsCorrectTargetArchitecture check here is in case if we forget what architecture our DLL (szDllFile) and target process (szProc) have
	if (!IsCorrectTargetArchitecture(hProc)) //check if that Injector and OpenProcess have same architecture (x86 and x86 or x64 and x64)
	{
		printf("Invalid target process.\n");
		CloseHandle(hProc); // We should close the HANDLE
		system("PAUSE");
		return 0;
	}
	//Entry to the ManualMap function with 'target process HANDLE' and 'path to the DLL file' as arguments:
	BOOL MMreturn = ManualMap(hProc, szDllFile); // <--
	if (!MMreturn) //  ManualMap returns 0 if something wrong
	{
		CloseHandle(hProc); //We should close HANDLE before system("PAUSE")
		printf("Something went wrong in ManualMap function. Exit.\n");
		system("PAUSE");
		return 0;
	}

	CloseHandle(hProc);
		
	return 0;
}