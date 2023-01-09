#include "DllInjection.h"

// The thread handle must be closed by the caller
HANDLE InjectDll(Process* proc, char* dllPath) {
	void* dllPathAddr = proc->AllocMemory(strlen(dllPath) + 1);
	proc->WriteMemory(dllPathAddr, (BYTE*)dllPath, strlen(dllPath) + 1);

	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
	void* loadLibraryAddr = GetProcAddress(kernel32, "LoadLibraryA");

	HANDLE hThread = CreateRemoteThread(proc->handle, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, dllPathAddr, 0, nullptr);
    if (!hThread)
    {
        std::cerr << "CreateRemoteThread error " << GetLastError() << std::endl;
    }
    return hThread;
}
