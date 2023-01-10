#include "Process.h"
#include "Utils.h"
#include <tlhelp32.h>

Process::Process(char* procName) 
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;

    // creates process snapshot
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        ThrowException("CreateToolhelp32Snapshot error");
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32))
    {
        ThrowException("Process32First error");
    }

    do // loops through processes
    {
        if (_strcmpi(procName, pe32.szExeFile) == 0)
        {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    if (!pid) 
    {
        ThrowException(std::string("Could not find process: ") + procName);
    }

    this->pid = pid;
}

Process::~Process()
{

}

bool Process::Open(DWORD access)
{
    this->handle = OpenProcess(access, false, this->pid);
    if (this->handle) 
    {
        return true;
    }
    return false;
}

void Process::Close()
{
    if (this->handle) 
    {
        CloseHandle(handle);
        this->handle = nullptr;
    }
}

// VirtualAllocEx with default parameters for convenience
LPVOID Process::AllocMemory(size_t size, LPVOID address, DWORD flProtect)
{
    return VirtualAllocEx(this->handle, address, size, MEM_COMMIT | MEM_RESERVE, flProtect);
}

// VirtualFreeEx with default parameters for convenience
BOOL Process::FreeMemory(LPVOID address) 
{
    return VirtualFreeEx(this->handle, address, 0, MEM_RELEASE);
}

// WriteProcessMemory with default parameters for convenience
BOOL Process::WriteMemory(LPVOID dest, BYTE* buffer, size_t size)
{
    return WriteProcessMemory(this->handle, dest, buffer, size, nullptr);
}
