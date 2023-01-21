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

    Process(char* procName);
    ~Process();

    bool Open(DWORD access = PROCESS_ALL_ACCESS);
    void Close();

    LPVOID AllocMemory(SIZE_T size, LPVOID address = nullptr, DWORD flProtect = PAGE_EXECUTE_READWRITE);
    BOOL FreeMemory(LPVOID address);
    BOOL WriteMemory(LPVOID dest, BYTE* buffer, SIZE_T size);
    BOOL ReadMemory(LPCVOID addr, BYTE* buffer, SIZE_T size);
    SIZE_T VirtualQuery(LPCVOID addr, PMEMORY_BASIC_INFORMATION pMemInfo);

    MODULEENTRY32 GetModule(char* modName);
};
