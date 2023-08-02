#include "DllInjection.h"

HANDLE InjectDll(Process& proc, char* dllPath)
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

    void* dllPathAddr = proc.AllocMemory(strlen(dll.filePath) + 1);
    proc.WriteMemory(dllPathAddr, (BYTE*)dll.filePath, strlen(dll.filePath) + 1);

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