#include "ManualMapping.h"
#include "../Common/Process.h"
#include "../Common/Constants.h"
#include <iostream>

int main(int argc, char** argv)
{
    char processName[MAX_LENGTH+1];
    char dllPath[MAX_PATH+1];

    if (argc == 3)
    {
        strncpy_s(processName, argv[1], MAX_LENGTH+1);
        strncpy_s(dllPath, argv[2], MAX_PATH+1);
    }
    else 
    {
        std::cout << "Process name:\n";
        std::cin.getline(processName, MAX_LENGTH+1);
        std::cout << "Dll path:\n";
        std::cin.getline(dllPath, MAX_PATH+1);
    }

    Process* proc = new Process(processName);
    if (proc->Open(PROCESS_CREATE_THREAD | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION))
    { 
        std::cout << "Manual mapping dll " << dllPath << " into process " << processName << "\n\n";
        if (ManualMapDll(proc, dllPath))
        {
            std::cout << "Dll injected successfully!\n";
        }
        else
        {
            std::cerr << "Could not inject the dll in the target process.\n";
        }
        proc->Close();
    }
    else 
    {
        std::cerr << "Could not open target process.\n";
    }
    delete proc;
    return 0;
}