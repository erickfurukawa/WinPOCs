#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include "WinInternals.h"

class Process
{
private:
    static bool Copy(const Process& from, Process& to);

public:
    DWORD pid = 0;
    std::string name = std::string();
    HANDLE handle = nullptr;
    HANDLE token = nullptr;
    bool is32Bits = false;

    Process() = default;
    Process(const char* procName);
    Process(DWORD pid);
    Process(const Process& process);
    Process& operator=(const Process& process);
    ~Process();

    bool Open(DWORD access = PROCESS_ALL_ACCESS);
    void Close();
    bool OpenProcessToken(DWORD access = TOKEN_ALL_ACCESS);
    void CloseProcessToken();
    bool Suspend();
    bool Resume();
    bool GetThreadIDs(std::vector<DWORD>& threadIDs);
    bool GetProcessInformation(ProcessInformation* pbi);
    LPVOID AllocMemory(SIZE_T size, LPVOID address = nullptr, DWORD flProtect = PAGE_EXECUTE_READWRITE);
    // alloc memory within a range
    LPVOID AllocMemory(SIZE_T size, LPVOID begin, LPVOID end, DWORD flProtect = PAGE_EXECUTE_READWRITE);
    BOOL FreeMemory(LPVOID address);
    BOOL WriteMemory(LPVOID dest, const BYTE* buffer, SIZE_T size, bool changeProtect = false);
    BOOL ReadMemory(LPCVOID addr, BYTE* buffer, SIZE_T size, bool changeProtect = false);
    BOOL VirtualProtect(LPVOID addr, SIZE_T size, DWORD newProtect, PDWORD pOldProtect = nullptr);
    SIZE_T VirtualQuery(LPCVOID addr, PMEMORY_BASIC_INFORMATION pMemInfo);
    BYTE* ScanMemory(BYTE* pattern, char* mask, PVOID addr, uintptr_t size);
    MODULEENTRY32 GetModule(const char* modName);
    MODULEENTRY32 GetMainModule();

    // ************************************ static methods ************************************

    /*
    * Starts a new process from exeFile.
    * The function might return before the process has finished initializing.
    */
    static Process NewProcess(const char* exeFile, DWORD dwCreationFlags = 0);

    /* 
    * Gets PROCESSENTRY32 of a process by name or pid.
    * If procName is null, pid is used, else, pid is ignored.
    */
    static bool GetProccessEntry(const char* procName, DWORD pid, PROCESSENTRY32* procEntry);
};
