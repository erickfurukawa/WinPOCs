#include "Process.h"
#include "Utils.h"
#include <iostream>

Process::Process(const char* procName)
{
    PROCESSENTRY32 pe32;
    if (Process::GetProccessEntry(procName, 0, &pe32))
    {
        this->pid = pe32.th32ProcessID;
        this->name = std::string(pe32.szExeFile);
        this->mainModule = this->GetModule(pe32.szExeFile);
    }
    else
    {
        ThrowException(std::string("Could not find process: ") + procName);
    }
}

Process::Process(DWORD pid)
{
    if (pid == 0)
    {
        pid = GetCurrentProcessId();
    }

    PROCESSENTRY32 pe32;
    if (Process::GetProccessEntry(nullptr, pid, &pe32))
    {
        this->pid = pe32.th32ProcessID;
        this->name = std::string(pe32.szExeFile);
        this->mainModule = this->GetModule(pe32.szExeFile);
    }
    else
    {
        ThrowException(std::string("Could not find process with PID: ") + std::to_string(pid));
    }
}

Process::~Process()
{

}

bool Process::Open(DWORD access)
{
    this->handle = OpenProcess(access, false, this->pid);
    if (this->handle) 
    {
        BOOL is32Bits;
        IsWow64Process(this->handle, &is32Bits);
        this->is32Bits = is32Bits ? true : false;
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

bool Process::GetThreadIDs(std::vector<DWORD> &threadIDs)
{
    HANDLE hThreadSnap;
    THREADENTRY32 te32{};

    // creates thread snapshot
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
    {
        std::cerr << "CreateToolhelp32Snapshot error " << GetLastError() << "\n";
        return false;
    }

    te32.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(hThreadSnap, &te32))
    {
        std::cerr << "Process32First error " << GetLastError() << "\n";
        CloseHandle(hThreadSnap);
        return false;
    }

    do // loops through threads
    {
        if (this->pid == te32.th32OwnerProcessID)
        {
            threadIDs.push_back(te32.th32ThreadID);
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
    return true;
}

bool Process::Suspend()
{
    std::vector<DWORD> threadIDs{};
    bool success = true;
    
    if (this->GetThreadIDs(threadIDs))
    {
        for (DWORD threadID : threadIDs)
        {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, false, threadID);
            if (!hThread)
            {
                success = false;
                std::cerr << "OpenThread error " << GetLastError() << "\n";
                break;
            }
            if (SuspendThread(hThread) == -1)
            {
                success = false;
                std::cerr << "SuspendThread error " << GetLastError() << "\n";
                CloseHandle(hThread);
                break;
            }
            CloseHandle(hThread);
        }
    }
    else
    {
        success = false;
        std::cerr << "Could not get thread IDs\n";
    }

    if (!success)
    {
        std::cerr << "Could not suspend process\n";
    }
    return success;
}

bool Process::Resume()
{
    std::vector<DWORD> threadIDs{};
    bool success = true;

    if (this->GetThreadIDs(threadIDs))
    {
        for (DWORD threadID : threadIDs)
        {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, false, threadID);
            if (!hThread)
            {
                success = false;
                std::cerr << "OpenThread error " << GetLastError() << "\n";
                break;
            }
            if (ResumeThread(hThread) == -1)
            {
                success = false;
                std::cerr << "ResumeThread error " << GetLastError() << "\n";
                CloseHandle(hThread);
                break;
            }
            CloseHandle(hThread);
        }
    }
    else
    {
        success = false;
        std::cerr << "Could not get thread IDs\n";
    }

    if (!success)
    {
        std::cerr << "Could not resume process\n";
    }
    return success;
}

LPVOID Process::AllocMemory(SIZE_T size, LPVOID address, DWORD flProtect)
{
    LPVOID addr = VirtualAllocEx(this->handle, address, size, MEM_COMMIT | MEM_RESERVE, flProtect);
    if (!addr)
    {
        std::cerr << "VirtualAllocEx error " << GetLastError() << "\n";
    }
    return addr;
}

LPVOID Process::AllocMemory(SIZE_T size, LPVOID begin, LPVOID end, DWORD flProtect)
{
    LPVOID addr = nullptr;
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uintptr_t currAddr = (reinterpret_cast<uintptr_t>(begin) & ~(static_cast<uintptr_t>(sysInfo.dwAllocationGranularity) - 1));
    if (reinterpret_cast<uintptr_t>(begin) % static_cast<uintptr_t>(sysInfo.dwAllocationGranularity) != 0)
    {   // need to go up dwAllocationGranularity bytes so that VirtualAllocEx doesn't return an address < begin
        currAddr += static_cast<uintptr_t>(sysInfo.dwAllocationGranularity);
    }

    while (currAddr < reinterpret_cast<uintptr_t>(end))
    {
        addr = VirtualAllocEx(this->handle, reinterpret_cast<LPVOID>(currAddr), size, MEM_COMMIT | MEM_RESERVE, flProtect);
        if (addr)
        { 
            break;
        }
        currAddr += sysInfo.dwAllocationGranularity;
    }

    if (!addr)
    {
        std::cerr << "AllocMemory error: could not allocate memory in range." << "\n";
    }
    return addr;
}

BOOL Process::FreeMemory(LPVOID address) 
{
    BOOL success = VirtualFreeEx(this->handle, address, 0, MEM_RELEASE);
    if (!success)
    {
        std::cerr << "VirtualFreeEx error " << GetLastError() << "\n";
    }
    return success;
}

BOOL Process::WriteMemory(LPVOID dest, BYTE* buffer, SIZE_T size, bool changeProtect)
{
    DWORD oldProtect = 0;
    if (changeProtect) // change protection to write
    {
        if (!this->VirtualProtect(dest, size, PAGE_EXECUTE_READWRITE, &oldProtect))
            return FALSE;
    }

    BOOL success = WriteProcessMemory(this->handle, dest, buffer, size, nullptr);
    if (!success)
    {
        std::cerr << "WriteProcessMemory error " << GetLastError() << "\n";
    }

    if (changeProtect) // restore protection
    {
        if (!this->VirtualProtect(dest, size, oldProtect, &oldProtect))
            return FALSE;
    }
    return success;
}

BOOL Process::ReadMemory(LPCVOID addr, BYTE* buffer, SIZE_T size, bool changeProtect)
{
    DWORD oldProtect = 0;
    if (changeProtect) // change protection to read
    {
        if (!this->VirtualProtect(const_cast<LPVOID>(addr), size, PAGE_EXECUTE_READWRITE, &oldProtect))
            return FALSE;
    }

    BOOL success = ReadProcessMemory(this->handle, addr, buffer, size, nullptr);
    if (!success)
    {
        std::cerr << "ReadProcessMemory error " << GetLastError() << "\n";
    }

    if (changeProtect) // restore protection
    {
        if (!this->VirtualProtect(const_cast<LPVOID>(addr), size, oldProtect, &oldProtect))
            return FALSE;
    }
    return success;
}

BOOL Process::VirtualProtect(LPVOID addr, SIZE_T size, DWORD newProtect, PDWORD pOldProtect)
{
    DWORD oldProtect = 0;
    BOOL success = VirtualProtectEx(this->handle, addr, size, newProtect, &oldProtect);
    if (pOldProtect)
    {
        *pOldProtect = oldProtect;
    }
    if (!success)
    {
        std::cerr << "VirtualProtectEx error " << GetLastError() << "\n";
    }
    return success;
}

SIZE_T Process::VirtualQuery(LPCVOID addr, PMEMORY_BASIC_INFORMATION pMemInfo)
{
    SIZE_T memInfoSize = VirtualQueryEx(this->handle, addr, pMemInfo, sizeof(MEMORY_BASIC_INFORMATION));
    if (!memInfoSize)
    {
        std::cerr << "VirtualQueryEx error " << GetLastError() << "\n";
    }
    return memInfoSize;
}

BYTE* Process::ScanMemory(BYTE* pattern, char* mask, PVOID addr, uintptr_t size)
{
    MEMORY_BASIC_INFORMATION memInfo;
    BYTE* currAddr = reinterpret_cast<BYTE*>(addr);
    BYTE* matchAddr = nullptr;

    while (currAddr < reinterpret_cast<BYTE*>(addr) + size)
    {
        if (!this->VirtualQuery(currAddr, &memInfo))
        {
            std::cerr << "Could not scan memory\n";
            break;
        }

        // checks if it is inaccessible memory
        if (memInfo.State != MEM_COMMIT || memInfo.Protect == PAGE_NOACCESS)
        {
            currAddr += memInfo.RegionSize;
            continue;
        }

        DWORD oldProtect;
        if (VirtualProtectEx(this->handle, currAddr, memInfo.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            BYTE* buffer = new BYTE[memInfo.RegionSize];
            this->ReadMemory(currAddr, buffer, memInfo.RegionSize);
            VirtualProtectEx(this->handle, currAddr, memInfo.RegionSize, oldProtect, &oldProtect);

            BYTE* internalMatchAddr = ScanPattern(pattern, mask, buffer, memInfo.RegionSize);
            if (internalMatchAddr)
            {
                matchAddr = currAddr + (internalMatchAddr - buffer);
                delete[] buffer;
                break;
            }
            delete[] buffer;
        }
        else
        {
            std::cerr << "Could not change protection for address 0x" << std::hex << reinterpret_cast<uintptr_t>(currAddr) << ". Skipping...\n";
        }
        currAddr += memInfo.RegionSize;
    }
    return matchAddr;
}

MODULEENTRY32 Process::GetModule(const char* modName)
{
    HANDLE hModuleSnap;
    MODULEENTRY32 mod32;
    bool found = false;

    // creates process snapshot
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, this->pid);
    if (hModuleSnap == INVALID_HANDLE_VALUE)
    {
        std::cerr << "CreateToolhelp32Snapshot error\n";
        return MODULEENTRY32{ 0 };
    }

    mod32.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(hModuleSnap, &mod32))
    {
        CloseHandle(hModuleSnap);
        std::cerr << "Module32First error " << GetLastError();
        return MODULEENTRY32{ 0 };
    }

    do // loops through modules
    {
        if (_strcmpi(modName, mod32.szModule) == 0)
        {
            found = true;
            break;
        }
    } while (Module32Next(hModuleSnap, &mod32));

    CloseHandle(hModuleSnap);
    if (!found)
    {
        std::cerr << "Could not find module " << modName << "\n";
        mod32 = MODULEENTRY32{ 0 };
    }
    return mod32;
}

bool Process::GetProcessInformation(ProcessInformation* pbi)
{
    // find NtQueryInformationProcess function
    HMODULE hNtDll = LoadLibraryA("ntdll.dll");
    if (hNtDll == NULL)
    {
        std::cerr << "Could not find module ntdll.dll\n";
        return false;
    }

    f_NtQueryInformationProcess pNtQueryInformationProcess = (f_NtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (pNtQueryInformationProcess == NULL)
    {
        FreeLibrary(hNtDll);
        std::cerr << "Could not find NtQueryInformationProcess\n";
        return false;
    }

    // call NtQueryInformationProcess to get PROCESS_BASIC_INFORMATION
    ULONG sizeNeeded;
    NTSTATUS dwStatus = pNtQueryInformationProcess(this->handle, PROCESSINFOCLASS::ProcessBasicInformation, pbi, sizeof(ProcessInformation), &sizeNeeded);
    if (dwStatus != 0)
    {
        std::cerr << "NtQueryInformationProcess failed!\n";
        return false;
    }
    return true;
}

bool Process::GetProccessEntry(const char* procName, DWORD pid, PROCESSENTRY32* procEntry)
{
    bool success = false;
    bool byName = (procName != nullptr);

    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32{};

    // creates process snapshot
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap != INVALID_HANDLE_VALUE)
    {
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hProcessSnap, &pe32))
        {
            do // loops through processes
            {
                if (byName)
                {
                    if (_strcmpi(procName, pe32.szExeFile) == 0)
                    {
                        *procEntry = pe32;
                        success = true;
                        break;
                    }
                }
                else // by pid
                {
                    if (pid == pe32.th32ProcessID)
                    {
                        *procEntry = pe32;
                        success = true;
                        break;
                    }
                }
            } while (Process32Next(hProcessSnap, &pe32));
        }
        else
        {
            std::cerr << "Process32First error: " << GetLastError() << "\n";
        }
        CloseHandle(hProcessSnap);
    }
    else
    {
        std::cerr << "CreateToolhelp32Snapshot error: " << GetLastError() << "\n";
    }

    return success;
}