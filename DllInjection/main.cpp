#include "DllInjection.h"
#include "../Common/PE.h"

int main(int argc, char** argv)
{
    // TODO: flag options
    std::string processName {0};
    std::string dllPath {0};

    if (argc >= 3)
    {
        processName = std::string(argv[1]);
        dllPath = std::string(argv[2]);
    }
    else
    {
        std::cout << "Process name:\n";
        std::cin >> processName;
        std::cout << "Dll path:\n";
        std::cin >> dllPath;
    }

    Process proc = Process(processName.c_str());
    bool success = false;
    if (proc.Open(PROCESS_CREATE_THREAD | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION))
    {
        if (argc == 4) // unload dll
        {
            std::cout << "Unloading dll " << dllPath << " from process " << processName << std::endl;
            if (UnloadDll(proc, dllPath))
            {
                std::cout << "Dll has probably been unloaded successfully\n";
                success = true;
            }
            else
            {
                std::cerr << "Could not unload dll from the target process\n";
            }
        }
        else // inject dll
        {
            PE dll = PE(dllPath.c_str());
            std::cout << "Injecting dll " << dll.filePath << " into process " << processName << std::endl;
            HANDLE hThread = InjectDll(proc, dll);
            if (hThread)
            {
                CloseHandle(hThread);
                std::cout << "Dll has probably been injected successfully\n";
                success = true;
            }
            else
            {
                std::cerr << "Could not inject dll into the target process\n";
            }
        }
        proc.Close();
    }
    else
    {
        std::cerr << "Could not open target process\n";
    }

    if (success)
        return 0;
    return 1;
}
