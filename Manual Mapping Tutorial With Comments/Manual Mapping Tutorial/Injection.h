#pragma once

//All our header files and declarations here in Injection.h:

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

/*
About using:
'using' is a modern typedef (it has functionality of typedef + more): 
f_LoadLibraryA, f_GetProcAddress, f_DLL_ENTRY_POINT become a type
for example:
f_LoadLibraryA takes a const char* as parameter and return HINSTANCE
where HINSTANCE is something called a "handle to an instance" or "handle to a module."
The operating system uses this value to identify the executable (EXE) when it is loaded in memory. 
The instance handle is needed for certain Windows functions—for example, to load icons or bitmaps.
HMODULE and HINSTANCE are the same nowadays.
WINAPI is a __stdcall and WINAPI* is a __stdcall pointer
__stdcall is the calling convention used for the function. 
This tells the compiler the rules that apply for setting up the stack, pushing arguments and getting a return value.
__stdcall is the standard calling convention for the Microsoft Win32 API
So (WINAPI*) is needed here to represent that f_LoadLibraryA is a function and it should use __stdcall calling convention for compatibility reasons
If we will use x64 standard calling convention instead then this injector won't work with x86 applications
https://en.wikipedia.org/wiki/X86_calling_conventions for more details
*/
//function prototypes (We need this to run these functions in the target process with shellcode:
using f_LoadLibraryA	= HINSTANCE	(WINAPI*)(const char * lpLibFilename);
/*
actual LoadLibraryA function
https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
HMODULE LoadLibraryA(
  LPCSTR lpLibFileName - The name of the module. This can be either a library module (a .dll file) or an executable module (an .exe file).
);
*/
using f_GetProcAddress	= UINT_PTR	(WINAPI*)(HINSTANCE hModule, const char * lpProcName);
/*
actual GetProcAddress function
https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
FARPROC GetProcAddress(
  HMODULE hModule, - A handle to the DLL module that contains the function or variable.
  LPCSTR  lpProcName - The function or variable name, or the function's ordinal value.
);
*/
using f_DLL_ENTRY_POINT = BOOL		(WINAPI*)(void * hDll, DWORD dwReason, void * pReserved);
/*
actual DLL_ENTRY_POINT function
https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain
BOOL WINAPI DllMain(
  _In_ HINSTANCE hinstDLL, - A handle to the DLL module.
  _In_ DWORD     fdwReason, - indicates why the DLL entry-point function is being called
  _In_ LPVOID    lpvReserved - If fdwReason is DLL_PROCESS_ATTACH, lpvReserved is NULL for dynamic loads and non-NULL for static loads.
);
*/
struct MANUAL_MAPPING_DATA
{
	f_LoadLibraryA		pLoadLibraryA;
	f_GetProcAddress	pGetProcAddress;
	HINSTANCE			hMod;
};

bool ManualMap(HANDLE hProc, const char * szDllFile);