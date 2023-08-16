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
    // find address of FreeLibrary
    MODULEENTRY32 meKernel32 = proc.GetModule("kernel32.dll");
    PE kernel32 = PE(meKernel32.szExePath);
    DWORD freeLibraryRVA = kernel32.GetExportRVA("FreeLibrary");
    void* freeLibraryAddr = meKernel32.modBaseAddr + freeLibraryRVA;

    // get the module handle. it is the base address of the module
    // not sure it this works 100% of the time
    MODULEENTRY32 meDll = proc.GetModule(moduleName.c_str());
    DWORD64 moduleHandle = reinterpret_cast<DWORD64>(meDll.modBaseAddr);

    // call FreeLibrary
    HANDLE hThread = CreateRemoteThread(proc.handle, nullptr, 0, (LPTHREAD_START_ROUTINE)freeLibraryAddr, reinterpret_cast<LPVOID>(moduleHandle), 0, nullptr);
    if (!hThread)
    {
        std::cerr << "CreateRemoteThread error (FreeLibrary) " << GetLastError() << std::endl;
        return false;
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return true;
}