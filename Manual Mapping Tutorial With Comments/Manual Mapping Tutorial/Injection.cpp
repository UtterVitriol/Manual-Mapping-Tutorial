#include "Injection.h"

void __stdcall Shellcode(MANUAL_MAPPING_DATA * pData); //declaration of the function which is writen below the ManualMap function. 
//__stdcall is here for x86 applications for compatibility reasons. See explanations in header file

bool ManualMap(HANDLE hProc, const char * szDllFile)
{
	BYTE *					pSrcData		= nullptr;
	IMAGE_NT_HEADERS *		pOldNtHeader	= nullptr;
	IMAGE_OPTIONAL_HEADER * pOldOptHeader	= nullptr;
	IMAGE_FILE_HEADER *		pOldFileHeader	= nullptr;
	BYTE *					pTargetBase		= nullptr;

	if (GetFileAttributesA(szDllFile) == INVALID_FILE_ATTRIBUTES) //GetFileAttributesA is used here only to catch an error
	{
		//We return messages about any possible error to figure out whats wrong faster in case of error
		//Also it's a good protection in case of programm crashing - we should close HANDLE in any case. Otherwise we will be banned.
		printf("File doesn't exist\n"); 
		return false;
	}

	std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);
	//We created class File (ifstream - Stream class to read from file) with combination of flags
	//std::ios::binary | std::ios::ate - means binary mode AND initial position at the end (ate) of the file
	//reference - http://www.cplusplus.com/doc/tutorial/files/

	if (File.fail()) //true if a reading or writing operation fails or format error happens
	{
		printf("Opening the file failed: %X\n", (DWORD)File.rdstate()); //returns current internal error state flag http://www.cplusplus.com/reference/ios/ios/rdstate/
		File.close();
		return false;
	}

	auto FileSize = File.tellg(); //File.tellg() Returns the position of the current character in the input stream and the position type.
	//auto - Deduces the type of a declared variable from its initialization expression. https://docs.microsoft.com/en-us/cpp/cpp/auto-cpp?view=msvc-160
	if (FileSize < 0x1000) // there are probably no way to create a valid hack DLL on VS with size less than 4 kB
	{
		printf("Filesize is invalid.\n");
		File.close();
		return false;
	}

	pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)]; //UINT_PTR is a 64-bit unsigned integer under x64 architecture and 32-bit under x86
	//static_cast<UINT_PTR>(FileSize) converts FileSize type into unsigned integer type like (UINT_PTR)(FileSize)
	//(UINT_PTR)(FileSize) is a C-style cast, static_cast is one of C++ restrictive casts
	//static_cast is necessary here because we don't want to get an error while doing the injection
	//static_cast allow the compiler to check if the two data types are compatible
	//therefore we can catch possible error during compilation
	//https://stackoverflow.com/questions/103512/why-use-static-castintx-instead-of-intx - reference
	if (!pSrcData) //operator 'new' return NULL pointer if a resource cannot be allocated because not enough memory is available for it
	{
		printf("Memory allocating failed\n");
		File.close();
		return false;
	}

	File.seekg(0, std::ios::beg); 
	//seekg Sets the position of the next character to be extracted from the input stream
	//.seekg(0, std::ios::beg) means set position to the beggining of the File with offset 0
	File.read(reinterpret_cast<char*>(pSrcData), FileSize);
	//Extracts FileSize characters from the stream and stores them in the array pSrcData
	/*
	* About reinterpret_cast:
	When you convert for example int(12) to unsigned float(12.0f) your processor needs to invoke some calculations
	as both numbers has different bit representation.This is what static_cast stands for.

	On the other hand, when you call reinterpret_cast the CPU does not invoke any calculations.
	It just treats a set of bits in the memory like if it had another type.
	So when you convert int* to float* with this keyword, the new value(after pointer dereferecing) 
	has nothing to do with the old value in mathematical meaning
	https://stackoverflow.com/questions/573294/when-to-use-reinterpret-cast

	So reinterpret_cast is necessary is when interfacing with opaque data types.
	or we don't want to change our initial type: BYTE[]
	*/
	File.close();

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) //Here we check if we read a file which contain code or not
	{
		/*
		* About IMAGE_DOS_HEADER and e_magic:
		0x5A4D is "MZ" string that meand .exe file, more information here:
		//https://en.wikipedia.org/wiki/DOS_MZ_executable
		IMAGE_DOS_HEADER is a struct, we use it to check 'e_magic' value:
		typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
			WORD   e_magic;                     // Magic number - should be "MZ" or 0x5A4D for .exe files.
			...
			LONG   e_lfanew;                    // File address of new exe header
		} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;
		0x5A4D is used by almost all windows executable files.

		Why we check if our DLL is EXE ? Actually not EXE but PE - Portable Executable:
		The Portable Executable (PE) format is a file format for executables, object code, DLLs and others used in 
		32-bit and 64-bit versions of Windows operating systems. The PE format is a data structure that encapsulates 
		the information necessary for the Windows OS loader to manage the wrapped executable code.
		A PE file consists of a number of headers and sections that tell the dynamic linker how to map the file into memory.
		https://en.wikipedia.org/wiki/Portable_Executable#:~:text=The%20Portable%20Executable%20(PE)%20format,manage%20the%20wrapped%20executable%20code.
		So all files in Windows which contain an executable code should have Portable executable format.
		*/
		printf("Invalid file\n");
		delete[] pSrcData;
		return false;
	}
	pOldNtHeader	= reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	//pSrcData is a global pointer to our massive of chars (char*) where we wrote our DLL, 
	//reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew is an offset to Nt Header
	pOldOptHeader	= &pOldNtHeader->OptionalHeader; // we got addresses of structures here by using & 
	pOldFileHeader	= &pOldNtHeader->FileHeader; //because we want to use values of these structures
	/*
	What all of that headers mean:
	I would highly reccomend to download something like CFF Explorer (https://ntcore.com/?page_id=388) and open your DLL with that programm 
	It helps to understand what PE file looks like and which information the file contains:

	Any PE file starts with next two headers:
	First, we have Dos Header which contains instruction that this file cannot be run in DOS (Disk Operating System) and this file is PE (Portable Executable)
	Also in Dos Header we use address where information of NT Header starts
	Note: Dos Header was created after Windows98 where you could crash your entire system by running a code in dos
	Second, after Dos Header there is Nt Header. Nt Header contains File Header structure and Optional Header Structure, which contain additional information
	Note: Nt (New technology) is a reference to Windows NT family of operating systems

	*/

#ifdef _WIN64
	//This code will run in x64 version of injector
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) // pOldFileHeader->Machine contain info about architecture. AMD invented x64 architecture first therefore x64 based on AMD64
	{
		printf("Invalid platform\n"); //if we use x64 injector for x86 dll
		delete[] pSrcData;
		return false;
	}
#else
	//This code will run in x86 version of injector
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386) //x86 based on Intel 80386 processor (or I386). Note: x86 is an architecture, 32 is amount of bits in that architecture
	{
		printf("Invalid platform\n"); //if we use x86 injector for x64 dll
		delete[] pSrcData;
		return false;
	}
#endif

	// Probably It is better to place The working with DLL file part to the part before creating a HANDLE

	//Now we are going to allocate memory into target process
	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, reinterpret_cast<void*>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	/*
		About VirtualAllocEx:
		https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
		Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified process.
		If the function succeeds, the return value is the base address of the allocated region of pages.
		LPVOID VirtualAllocEx(
		  HANDLE hProcess, - The handle to a process. The function allocates memory within the virtual address space of this process

		  LPVOID lpAddress, - The pointer that specifies a desired starting address for the region of pages that you want to allocate
							more specified informations about imageBase and SizeOfImage and what an Image is can be found here:
							https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#:~:text=This%20specification%20describes%20the%20structure,(COFF)%20files%2C%20respectively.
							https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)?redirectedfrom=MSDN
							image is like another abstract name of an executable file (Portable Executable), because PE is like an image in memory which parts (pieces) are stored 
							in the memory and we can find these parts of the image by following pointers in the headers.
							ImageBase is the preferred address of the first byte of image when loaded into memory. The default for DLLs is 0x10000000. 
							VirtualAllocEx function can determines where to allocate the region. 
							-> so this is not a necessary parameter but it can help the function work faster and avoid large offsets

		  SIZE_T dwSize, - The size of the region of memory to allocate, in bytes.
							SizeOfImage - This appears to be the total size (in bytes) of the portions of the image that the loader has to worry about,
							including all headers. It is the size of the region starting at the image base up to the end of the last section.
							IMAGE_OPTIONAL_HEADER.SizeOfImage is the size of the loaded executable/dll in virtual memory. It is not the same as the size on disk.
							This size can be at times greater than actual PE file size on disk. 
							You can calculate it with VirtualAddress + VirtualSize of the last section (.reloc in Section Headers, use CFF Explorer) - 
							- this value rounded up to the value of IMAGE_OPTIONAL_HEADER.SectionAlignment (usually the same as the page size).
							-> the PE file has sections which allocated in the memory with larger distance between each other. 

		  DWORD  flAllocationType, - The type of memory allocation
							MEM_COMMIT | MEM_RESERVE - To reserve and commit pages in one step
							MEM_COMMIT - Allocates memory charges (from the overall size of memory and the paging files on disk) for the specified reserved memory pages.
							MEM_RESERVE - Other memory allocation functions, such as malloc and LocalAlloc, cannot use reserved memory until it has been released.
							-> we want to use this allocated memory later

		  DWORD  flProtect - The memory protection for the region of pages to be allocated. If the pages are being committed, you can specify any one of the memory protection constants
							PAGE_EXECUTE_READWRITE - Enables execute, read-only, or read/write access to the committed region of pages.
							-> we need write access to the committed region
		);
	*/
	if (!pTargetBase)
	{
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		//another try without preferred address
		if (!pTargetBase)
		{
			printf("Memory allocation failed (ex) 0x%X\n", GetLastError());
			//it can happen either if your target process out of run or an anticheat protects target process in some way
			delete[] pSrcData;
			return false;
		}
	}

	MANUAL_MAPPING_DATA data{ 0 }; //Initialize the structure which was declarated
	data.pLoadLibraryA		= LoadLibraryA;
	/*
	  https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
	Loads the specified module into the address space of the calling process. The specified module may cause other modules to be loaded.
	HMODULE LoadLibraryA(
	  LPCSTR lpLibFileName - The name of the module. This can be either a library module (a .dll file) or an executable module (an .exe file).
	);
	*/
	data.pGetProcAddress	= reinterpret_cast<f_GetProcAddress>(GetProcAddress); //reinterpret_cast is used here because f_GetProcAddress defined different (return UINT_PTR)
	/*
	  https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
	Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL)
	FARPROC GetProcAddress(
	  HMODULE hModule, - A handle to the DLL module that contains the function or variable.
	  LPCSTR  lpProcName - The function or variable name, or the function's ordinal value.
	);
	*/
	
	auto * pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader); 
	/*
	* About Macro:
	* IMAGE_FIRST_SECTION is a macro (https://en.cppreference.com/w/cpp/preprocessor/replace): 
	#define IMAGE_FIRST_SECTION(ntheader)( (PIMAGE_SECTION_HEADER)((ULONG_PTR)(ntheader) + FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) + ((ntheader))->FileHeader.SizeOfOptionalHeader) )
	#define FIELD_OFFSET(type, field)    ((LONG)(LONG_PTR)&(((type *)0)->field))
	Syntax: (#define identifier( parameters ) replacement-list)
	=>  FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) is offset from NtHeader to OptionalHeader, 
		((ntheader))->FileHeader.SizeOfOptionalHeader) ) is size of Optional Header
		And therefore IMAGE_FIRST_SECTION returns address of first section in Section Headers
		This thing can be easily calculated and checked in hex editor (first section usually is .text for Release DLL and .textbss for Debug DLL) with help of CFF Explorer (or analogue)
	*/

	/*
	* pSectionHeader will have IMAGE_SECTION_HEADER type:
	typedef struct _IMAGE_SECTION_HEADER {
		BYTE    Name[IMAGE_SIZEOF_SHORT_NAME]; - name (.text, .rdata, .data, .rsrc, .reloc ...)
		union {
				DWORD   PhysicalAddress;
				DWORD   VirtualSize; - the actual size of the code or data. This is the size before rounding up to the nearest file alignment multiple.									   
		} Misc;
		DWORD   VirtualAddress; - Relative Virtual Address (RVA) to where the loader should map the section. The first section defaults to an RVA of 0x1000
		DWORD   SizeOfRawData; - the size of the section (size of the data section rounded up)
		DWORD   PointerToRawData; - pointer to the raw address, the actual address of the section data in the file
		DWORD   PointerToRelocations;
		DWORD   PointerToLinenumbers;
		WORD    NumberOfRelocations;
		WORD    NumberOfLinenumbers;
		DWORD   Characteristics;
	} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
	https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)?redirectedfrom=MSDN
	*/
	/*
	Why do we need to map sections?
	The PE file on disk is "compressed". Some sections don't even exist in the raw file. 
	The section header contains the required information for the "runtime version" of the file.	
	Sections are just 'blocks' of data that are contained in the DLL. 
	For example, the .reloc section holds all the data needed to do the relocations, the .rdata holds all data that needs to be in read-only memory etc.
	*/
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) //++pSectionHeader - next pointer to next section
	{
		//#define IMAGE_SIZEOF_SECTION_HEADER 40 => ++pSectionHeader moves the pointer to the code where the current struct of section header ends (+ 0x28 or 40)
		if (pSectionHeader->SizeOfRawData) //additional check
		{
			/*
			https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
			If the function succeeds, the return value is nonzero.
			BOOL WriteProcessMemory(
			  HANDLE  hProcess, - HANDLE to the target process
			  LPVOID  lpBaseAddress, - address of the allocated memory for the section
			  LPCVOID lpBuffer, - address of the data which should be writen into process memory
			  SIZE_T  nSize, - size of the data section
			  SIZE_T  *lpNumberOfBytesWritten - A pointer to a variable that receives the number of bytes transferred into the specified process. This parameter is optional.
			);
			*/
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) //Write Sections
			{
				printf("Can't map sections: 0x%x\n", GetLastError());
				delete[] pSrcData;
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE); //clean up allocated memory
				return false;
			}
		}
	}

	
	memcpy(pSrcData, &data, sizeof(data));
	/*
	Data overrides pSrcdata here. The data structure is only 12 / 24 bytes big and the first 12 / 24 bytes of the DOS header are irrelevant at this point.
	For the sake of simplicity Broihon decided to avoid additional memory allocations and used already allocated memory to the store the required data.
	To make this staff correct we should allocate memory for data structure and rewrite some things in shellcode function.
	*/
	WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr); //Write PE Headers (first 0x1000 bytes are reserved for the headers) of data into the target process
	delete[] pSrcData; //we don't need this anymore

	void * pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); //0x1000 hardcode 4 kB for shellcode which should be more than enought
	if (!pShellcode)
	{
		printf("Memory allocation failed (1) (ex) 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr); //Write shellcode to the process
	/*
		The 0x1000 is just an "estimate" to make sure the whole function gets copied. 0x1000 is more than enough for this function.
	*/

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr); //Run shellcode in the process
	/*
	Creates a thread that runs in the virtual address space of another process.
	HANDLE CreateRemoteThread(					
		HANDLE                 hProcess,			- A handle to the process in which the thread is to be created.
		LPSECURITY_ATTRIBUTES  lpThreadAttributes,  - If lpThreadAttributes is NULL, the thread gets a default security descriptor and the handle cannot be inherited.
		SIZE_T                 dwStackSize,			- If this parameter is 0 (zero), the new thread uses the default size for the executable.
		LPTHREAD_START_ROUTINE lpStartAddress,		- A pointer to the application-defined function of type LPTHREAD_START_ROUTINE to be executed by the thread
													and represents the starting address of the thread in the remote process. The function must exist in the remote process.
		LPVOID                 lpParameter,			- A pointer to a variable to be passed to the thread function.
		DWORD                  dwCreationFlags,		- 0 => The thread runs immediately after creation.
		LPDWORD                lpThreadId			- If this parameter is NULL, the thread identifier is not returned.
	); If the function fails, the return value is NULL. 
	*/
	if (!hThread)
	{		
		printf("Thread creation failed 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}	
	CloseHandle(hThread);

	//We should deallocate the shellcode. And we need to write a code that checks if the shellcode finished or not
	HINSTANCE hCheck = NULL;
	while (!hCheck)
	{
		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProc, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;
		Sleep(10);
	}
	VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);

	return true;
}

//Macro for relocations in shellcode
#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW) 
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
/*
shift RelInfo right on 12. RelInfo has WORD type (see below). For example if RelInfo is '1010 1111 0000 1111' after operation >> 0x0C it becomes '1010'
These bits '1010' are represent type in the relocation table: https://stackoverflow.com/questions/17436668/how-are-pe-base-relocations-build-up
This number is compared with 0011 in x86 architecture or with 1010 in x64
IMAGE_REL_BASED_HIGHLOW - The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
IMAGE_REL_BASED_DIR64   - The base relocation applies the difference to the 64-bit field at offset.
https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only
You can also look how this relocation table looks like with CFF Explorer in Relocation Directory of your DLL
*/

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

void __stdcall Shellcode(MANUAL_MAPPING_DATA * pData)
{
	if (!pData) //If NULL
		return;

	//We use pData for two things here: 1) for pointer to the base address of the data structure and 2) for pointer to relocations Dll data (headers)
	//This was made for simplicity and there is the first improvement that should be done in this code in future modifications
	BYTE * pBase = reinterpret_cast<BYTE*>(pData); //Note in case: we can cast pointers in whatever we want
	auto * pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader; //e_lfanew is an offset to Nt Headers 

	auto _LoadLibraryA		= pData->pLoadLibraryA;
	auto _GetProcAddress	= pData->pGetProcAddress;
	auto _DllMain			= reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint); 
	//AddressOfEntryPoint is offset to dll entry point after allocating section .text in memory
	
	BYTE * LocationDelta = pBase - pOpt->ImageBase; //ImageBase is preferred address for the DLL, pBase is actual address
	if (LocationDelta) //if actual address of the DLL is not equal to preferred
	{
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;
		/*
		All memory addresses in the code / data sections of a library are stored relative to the address defined by ImageBase in the OptionalHeader. 
		If the library can’t be imported to this memory address, the references must get adjusted => relocated. 
		The file format helps for this by storing informations about all these references in the base relocation table, 
		which can be found in the directory entry 5 of the DataDirectory in the OptionalHeader.
		This table consists of a series of this structure:
		typedef struct _IMAGE_DATA_DIRECTORY {
			DWORD   VirtualAddress;
			DWORD   Size;
		} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
		It contains (SizeOfBlock – IMAGE_SIZEOF_BASE_RELOCATION) / 2 entries of 16 bits each. 
		The upper 4 bits define the type of relocation, the lower 12 bits define the offset relative to the VirtualAddress.
		https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/
		DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size is Relocation Directory Size. Same as .reloc Virtual Size in Section Headers

		The .reloc section is a list of places in the image where the difference between the linker assumed load address and the actual load address needs to be factored in.
		https://www.codeproject.com/Articles/12532/Inject-your-code-to-a-Portable-Executable-file#ImplementRelocationTable7_2
		By relocation, some values inside the virtual memory are corrected according to the current image base by the ".reloc" section packages.
		delta_ImageBase = current_ImageBase - image_nt_headers->OptionalHeader.ImageBase
		mem[ current_ImageBase + 0x1000 ] = mem[ current_ImageBase + 0x1000 ] + delta_ImageBase ;
		*/

		auto * pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress); //get pointer to .reloc
		/*
		typedef struct _IMAGE_BASE_RELOCATION {
			DWORD   VirtualAddress;
			DWORD   SizeOfBlock;
			//  WORD    TypeOffset[1];
		} IMAGE_BASE_RELOCATION;
		*/
		while (pRelocData->VirtualAddress)
		{
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); // (SizeOfBlock - Structure in the beginning)/(65535 or 0xFFFF or 16 bits)
			WORD * pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1); //Data after struct IMAGE_BASE_RELOCATION

			for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) //pRelativeInfo increment 1 WORD here
			{
				if (RELOC_FLAG(*pRelativeInfo)) // if *pRelativeInfo has type 3 or 10 (in x86 or x64 respectively)
				{
					UINT_PTR * pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF)); //*pRelativeInfo & 0xFFF get rid of type
					//For newbs: (1010 1100 1001 1111) & (0000 1111 1111 1111) = (1100 1001 1111) It is called Bitwise operation - https://en.wikipedia.org/wiki/Bitwise_operation				
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta); //Add to *pRelativeInfo (without type) a LocationDelta offset here
					/*
					addresses& and pointers* in C:
					https://beginnersbook.com/2014/01/c-pointers/#:~:text=A%20pointer%20is%20a%20variable,address%20of%20a%20integer%20variable.
					pPatch is a pointer to a cell in the relocation table. It is little bit difficult to figure out how relocation table looks like to understand what is going on here.
					The better way to understand this is watch a relocation table with CFF Explorer as was mentioned above. pPatch is a pointer to a cell which contain an address (RVA)
					LocationDelta is added to the value in the cell (is added ro RVA)
					*/
				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock); //next block
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) //Import Directory RVA/Size
	{
		auto * pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress); //Pointer to Import Directory
		/*
		IAT - Import Address Table https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
		typedef struct _IMAGE_IMPORT_DESCRIPTOR {
			union {									//OFTs
				DWORD   Characteristics;            // 0 for terminating null import descriptor
				DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
			} DUMMYUNIONNAME;
			DWORD   TimeDateStamp;                  // 0 if not bound,
													// -1 if bound, and real date\time stamp
													//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
													// O.W. date/time stamp of DLL bound to (Old BIND)

			DWORD   ForwarderChain;                 // -1 if no forwarders. The index of the first forwarder reference.
			DWORD   Name;							// Name RVA. The address of an ASCII string that contains the name of the DLL. This address is relative to the image base.
			DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses). The RVA of the import address table. 
													   The contents of this table are identical to the contents of the import lookup table until the image is bound.
													   In Other words OriginalFirstThunk = FirstThunk until the image is bound.
		} IMAGE_IMPORT_DESCRIPTOR;
		About bound import:
		For bound imports, the linker saves the timestamp and checksum of the DLL to which the import is bound. 
		At run-time Windows checks to see if the same version of library is being used, and if so, Windows bypasses processing the imports. 
		Otherwise, if the library is different from the one which was bound to, Windows processes the imports in a normal way.
		For example, all the standard Windows applications are bound to the system DLLs of their respective Windows release.
		*/
		while (pImportDescr->Name)// If new DLL Import is found
		{
			char * szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name); //The name of DLL to Import
			HINSTANCE hDll = _LoadLibraryA(szMod); //Get Handle to that Dll. 
			//It is Important to use defined functions in the beggining (auto _LoadLibraryA = pData->pLoadLibraryA;). Otherwise shellcode won't determine the functions. 

			ULONG_PTR * pThunkRef	= reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR * pFuncRef	= reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef) //There is a chance that OriginalFirstThunk is not define. In this case we don't want to get an error.
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				/*
				Function import can be start using either function name or ordinal number:
				Something like GetProcAddress(lib, "ReadProcessMemory") or GetProcAddress(lib, (char*)42)
				*/				
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) //If the function import by ordinal number or function name
				{
					/*
					* IMAGE_SNAP_BY_ORDINAL:
					#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)
					IMAGE_ORDINAL_FLAG32 = 0x80000000

					If *pThunkRef has High bit (0x80000000) then *pThunkRef Low bits (0xFFFF) contain Ordinal number and *pThunkRef has structure:
					typedef struct _IMAGE_THUNK_DATA32 {
						union {
							DWORD ForwarderString;      // PBYTE
							DWORD Function;             // PDWORD
							DWORD Ordinal;
							DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
						} u1;
					} IMAGE_THUNK_DATA32;
					(This structure can not be seen in CFF Explorer, in this case another editor is needed, but sme structure can be seen in Export Directory for some Dll)
					Else if *pThunkRef doesn't have High bit then *pThunkRef Low bits (0xFFFF) contain Name and *pThunkRef has structure:
					typedef struct _IMAGE_IMPORT_BY_NAME {
						WORD    Hint;   - number of the function
						BYTE    Name[1];
					} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
					This structure can be seen in CFF Explorer
					*/
					*pFuncRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF)); //add ProcAddress of the function in dll to FirstThunk (FTs or IAT) by number
				}
				else
				{
					auto * pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name); //add ProcAddress of the function in dll to FirstThunk (FTs or IAT) by name
				}
			}
			++pImportDescr;
		}
	}
	//thread local storage (TLS). We need to execute TLSs
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) //it is usually 0 for simple hacks which don't contain opened threads
	{
		auto * pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto * pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		/*
		About TLS:
		The TLS array is an array of addresses that the system maintains for each thread. 
		Each address in this array gives the location of TLS data for a given module (EXE or DLL) within the program. 
		The TLS index indicates which member of the array to use. The index is a number (meaningful only to the system) that identifies the module.
		https://docs.microsoft.com/ru-ru/windows/win32/debug/pe-format?redirectedfrom=MSDN
		The best explanation is here:
		https://docs.microsoft.com/en-us/windows/win32/procthread/thread-local-storage

		Therefore: If you didn't create a thread in Dll with CreateThread() function then TLS Size and VirtualAddress are set to 0
		*/
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr); // start APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpr) function of our injected DLL

	pData->hMod = reinterpret_cast<HINSTANCE>(pBase); //Mark for ManualMap function that this shellcode is completed.
}