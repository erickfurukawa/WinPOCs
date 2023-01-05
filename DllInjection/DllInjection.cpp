#include <iostream>
#include "../Common/Constants.h"
#include "../Common/Process.h"

bool injectDll(HANDLE hProc, char* dllPath);

int main(int argc, char** argv)
{
    char processName[MAX_LENGTH];
    char dllPath[MAX_LENGTH];

    if (argc == 3) {
        strncpy_s(processName, argv[1], MAX_LENGTH);
        strncpy_s(dllPath, argv[2], MAX_LENGTH);
    }
    else {
        std::cout << "Process name:\n";
        std::cin.getline(processName, MAX_LENGTH);
        std::cout << "Dll path:\n";
        std::cin.getline(dllPath, MAX_LENGTH);
    }

    std::cout << "Injecting dll " << dllPath <<  " into process " << processName << std::endl;

    DWORD pid = GetPid(processName);
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, true, pid);

    if (!hProc)
    {
        std::cerr << "OpenProccess error " << GetLastError() << std::endl;
        return 1;
    }

    if (!injectDll(hProc, dllPath))
    {
        CloseHandle(hProc);
        std::cerr << "Could not inject dll in the target process" << std::endl;
        return 1;
    }

    CloseHandle(hProc);
    std::cout << "Dll injected successfully" << std::endl;
    return 0;
 
}

bool injectDll(HANDLE hProc, char* dllPath) {
	void* dllPathAddr = AllocMem(hProc, strlen(dllPath) + 1);
	WriteMem(hProc, dllPathAddr, (BYTE*)dllPath, strlen(dllPath) + 1);

	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
	void* loadLibraryAddr = GetProcAddress(kernel32, "LoadLibraryA");

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, dllPathAddr, 0, nullptr);
    if (!hThread)
    {
        std::cerr << "CreateRemoteThread error " << GetLastError() << std::endl;
        return false;
    }

    CloseHandle(hThread);
    return true;
}
