#include "DllInjection.h"

HANDLE InjectDll(Process& proc, const char* dllPath)
{
    PE dll(dllPath);
    return InjectDll(proc, dll);
}

HANDLE InjectDll(Process& proc, PE& dll)
{
    if (proc.is32Bits != dll.is32Bits)
    {
        std::cerr << "Process and dll bitness are different!\n";
        return nullptr;
    }

    void* dllPathAddr = proc.AllocMemory(dll.filePath.length() + 1);
    proc.WriteMemory(dllPathAddr, (BYTE*)dll.filePath.c_str(), dll.filePath.length() + 1);

    // find address of LoadLibraryA.
    // needs to find base address of kernel32.dll and the function RVA
    MODULEENTRY32 meKernel32 = proc.GetModule("kernel32.dll");
    PE kernel32 = PE(meKernel32.szExePath);
    DWORD loadLibraryRVA = kernel32.GetExportRVA("LoadLibraryA");
    void* loadLibraryAddr = meKernel32.modBaseAddr + loadLibraryRVA;

    HANDLE hThread = CreateRemoteThread(proc.handle, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, dllPathAddr, 0, nullptr);
    if (!hThread)
    {
        std::cerr << "CreateRemoteThread error " << GetLastError() << std::endl;
        std::cerr << "Could not inject dll " << dll.filePath << " into the target process " << proc.name << std::endl;
    }
    return hThread;
}

bool UnloadDll(Process& proc, std::string moduleName)
{
    void* dllPathAddr = proc.AllocMemory(moduleName.length() + 1);
    proc.WriteMemory(dllPathAddr, (BYTE*)moduleName.c_str(), moduleName.length() + 1);

    // find address of GetModuleHandleA and FreeLibrary
    MODULEENTRY32 meKernel32 = proc.GetModule("kernel32.dll");
    PE kernel32 = PE(meKernel32.szExePath);
    DWORD getModuleHandleRVA = kernel32.GetExportRVA("GetModuleHandleA");
    DWORD freeLibraryRVA = kernel32.GetExportRVA("FreeLibrary");
    void* getModuleHandleAddr = meKernel32.modBaseAddr + getModuleHandleRVA;
    void* freeLibraryAddr = meKernel32.modBaseAddr + freeLibraryRVA;

    // get module handle
    HANDLE hThread = CreateRemoteThread(proc.handle, nullptr, 0, (LPTHREAD_START_ROUTINE)getModuleHandleAddr, dllPathAddr, 0, nullptr);
    if (!hThread)
    {
        std::cerr << "CreateRemoteThread error (GetModuleHandleA) " << GetLastError() << std::endl;
        proc.FreeMemory(dllPathAddr);
        return false;
    }
    DWORD returnValue = 0;
    WaitForSingleObject(hThread, INFINITE);
    GetExitCodeThread(hThread, reinterpret_cast<LPDWORD>(&returnValue));
    CloseHandle(hThread);
    DWORD64 moduleHandle = returnValue;

    // if 64 bits, the module handle value might be the base address of the file
    // not sure if this works everytime
    if (!proc.is32Bits)
    {
        MODULEENTRY32 meDll = proc.GetModule(moduleName.c_str());
        moduleHandle = reinterpret_cast<DWORD64>(meDll.modBaseAddr);
    }

    // free library
    hThread = CreateRemoteThread(proc.handle, nullptr, 0, (LPTHREAD_START_ROUTINE)freeLibraryAddr, reinterpret_cast<LPVOID>(moduleHandle), 0, nullptr);
    if (!hThread)
    {
        std::cerr << "CreateRemoteThread error (FreeLibrary) " << GetLastError() << std::endl;
        proc.FreeMemory(dllPathAddr);
        return false;
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    proc.FreeMemory(dllPathAddr);
    return true;
}