#pragma once

#include <windows.h>

using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

typedef struct ManualMappingData
{
    DWORD status;
    BYTE* baseAddr;
    HMODULE(__stdcall* pLoadLibraryA)(LPCSTR lpLibFilename);
    FARPROC(__stdcall* pGetProcAddress)(HMODULE hmodule, LPCSTR lpProcName);
} ManualMappingData;

void __stdcall Shellcode(ManualMappingData* data);
