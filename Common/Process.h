#pragma once

#include <windows.h>
#include <tlhelp32.h>

class Process
{
private:
    Process(const Process&);
    Process& operator=(const Process&);

public:
    DWORD pid = 0;
    HANDLE handle = nullptr;
    MODULEENTRY32 mainModule;
    bool is32Bits;

    Process(const char* procName);
    ~Process();

    bool Open(DWORD access = PROCESS_ALL_ACCESS);
    void Close();

    LPVOID AllocMemory(SIZE_T size, LPVOID address = nullptr, DWORD flProtect = PAGE_EXECUTE_READWRITE);
    // alloc memory within a range
    LPVOID AllocMemory(SIZE_T size, LPVOID begin, LPVOID end, DWORD flProtect = PAGE_EXECUTE_READWRITE);
    BOOL FreeMemory(LPVOID address);
    BOOL WriteMemory(LPVOID dest, BYTE* buffer, SIZE_T size, bool changeProtect = false);
    BOOL ReadMemory(LPCVOID addr, BYTE* buffer, SIZE_T size, bool changeProtect = false);
    BOOL VirtualProtect(LPVOID addr, SIZE_T size, DWORD newProtect, PDWORD pOldProtect = nullptr);
    SIZE_T VirtualQuery(LPCVOID addr, PMEMORY_BASIC_INFORMATION pMemInfo);
    BYTE* ScanMemory(BYTE* pattern, char* mask, PVOID addr, uintptr_t size);
    MODULEENTRY32 GetModule(const char* modName);
};
