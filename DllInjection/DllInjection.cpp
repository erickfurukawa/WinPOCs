#include "DllInjection.h"
#include "../Common/PE.h"

// The thread handle must be closed by the caller
HANDLE InjectDll(Process* proc, char* dllPath) {
    void* dllPathAddr = proc->AllocMemory(strlen(dllPath) + 1);
    proc->WriteMemory(dllPathAddr, (BYTE*)dllPath, strlen(dllPath) + 1);

    // find address of LoadLibraryA.
    // needs to find base address of kernel32.dll and the function RVA
    MODULEENTRY32 meKernel32 = proc->GetModule("kernel32.dll");
    PE* kernel32 = new PE(meKernel32.szExePath);
    DWORD loadLibraryRVA = kernel32->GetExportRVA("LoadLibraryA");
    delete kernel32;
    void* loadLibraryAddr = meKernel32.modBaseAddr + loadLibraryRVA;
    
    HANDLE hThread = CreateRemoteThread(proc->handle, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, dllPathAddr, 0, nullptr);
    if (!hThread)
    {
        std::cerr << "CreateRemoteThread error " << GetLastError() << std::endl;
        std::cerr << "Could not inject dll " << dllPath << " into the target process " << proc->mainModule.szModule << std::endl;
    }
    return hThread;
}
