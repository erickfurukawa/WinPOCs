#pragma once

#include <windows.h>

using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

typedef struct ManualMappingData
{
    DWORD status;
    BYTE* baseAddr;
    HMODULE(__stdcall* pLoadLibraryA)(LPCSTR lpLibFilename);
    FARPROC(__stdcall* pGetProcAddress)(HMODULE hmodule, LPCSTR lpProcName);
} ManualMappingData;

void __stdcall Shellcode(ManualMappingData* data);
