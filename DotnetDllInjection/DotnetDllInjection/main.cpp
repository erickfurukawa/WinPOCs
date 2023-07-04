#include <iostream>
#include "DotnetDllInjection.h"
#include "../../Common/Utils.h"

int main(int argc, char** argv)
{
    char processName[MAX_LENGTH + 1];
    char dotnetDllPath[MAX_PATH + 1];
    char methodName[MAX_LENGTH + 1];
    char argument[MAX_LENGTH + 1];

    char loaderPath[] = "dotnetDllLoader.dll";

    if (argc == 5)
    {
        strncpy_s(processName, argv[1], MAX_LENGTH + 1);
        strncpy_s(dotnetDllPath, argv[2], MAX_PATH + 1);
        strncpy_s(methodName, argv[3], MAX_LENGTH + 1);
        strncpy_s(argument, argv[4], MAX_LENGTH + 1);
    }
    else
    {
        std::cout << "Process name:\n";
        std::cin.getline(processName, MAX_LENGTH + 1);
        std::cout << "Dotnet dll path:\n";
        std::cin.getline(dotnetDllPath, MAX_PATH + 1);
        std::cout << "Method to run:\n";
        std::cin.getline(methodName, MAX_LENGTH + 1);
        std::cout << "String argument:\n";
        std::cin.getline(argument, MAX_LENGTH + 1);
    }

    PE dll = PE(dotnetDllPath);
    Process proc = Process(processName);
    bool success = false;
    if (proc.Open(PROCESS_CREATE_THREAD | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION))
    {
        std::cout << "Dll '" << dll.filePath << "' will be injected into process '" << processName << "'\n";
        std::cout << "Method '" << methodName << "' will be called with arguments '" << argument << "'\n";
        if (InjectDotnetDll(proc, dll, methodName, argument))
        {
            std::cout << "Dll has probably been injected successfully\n";
            success = true;
        }
        else
        {
            std::cerr << "Could not inject .NET dll into the target process\n";
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
