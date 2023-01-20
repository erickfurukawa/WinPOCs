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

    LPVOID AllocMemory(size_t size, LPVOID address = nullptr, DWORD flProtect = PAGE_EXECUTE_READWRITE);
    BOOL FreeMemory(LPVOID address);
    BOOL WriteMemory(LPVOID dest, BYTE* buffer, size_t size);
    int ReadMemory(LPCVOID addr, BYTE* buffer, size_t size);

    MODULEENTRY32 GetModule(char* modName);
};
