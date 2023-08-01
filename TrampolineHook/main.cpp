#include <iostream>
#include "TrampolineHook.h"
#include "../Common/Constants.h"
#include "../Common/Utils.h"


int main(int argc, char** argv)
{
    char processName[MAX_LENGTH];
    char targetModule[MAX_LENGTH];
    char targetFunction[MAX_LENGTH];
    char hookDll[MAX_PATH];
    char hookFunction[MAX_LENGTH];

    if (argc == 6)
    {
        strncpy_s(processName, argv[1], MAX_LENGTH);
        strncpy_s(targetModule, argv[2], MAX_LENGTH);
        strncpy_s(targetFunction, argv[3], MAX_LENGTH);
        strncpy_s(hookDll, argv[4], MAX_PATH);
        strncpy_s(hookFunction, argv[5], MAX_LENGTH);
    }
    else
    {
        std::cout << "Process name:\n";
        std::cin.getline(processName, MAX_LENGTH);
        std::cout << "Target module:\n";
        std::cin.getline(targetModule, MAX_LENGTH);
        std::cout << "Target function :\n";
        std::cin.getline(targetFunction, MAX_LENGTH);
        std::cout << "Hook dll:\n";
        std::cin.getline(hookDll, MAX_PATH);
        std::cout << "Hook function :\n";
        std::cin.getline(hookFunction, MAX_LENGTH);
    }

    if (!FileExists(hookDll))
    {
        std::cerr << "Could not open file hook dll " << hookDll << "\n";
        return 1;
    }

    Process proc = Process(processName);
    bool success = false;
    if (proc.Open())
    {
        if (InstallTrampolineHook(proc, targetModule, targetFunction, hookDll, hookFunction))
        {
            std::cout << "Trampoline hook installed successfully!\n";
            success = true;
        }
        proc.Close();
    }

    if (success)
        return 0;
    return 1;
}