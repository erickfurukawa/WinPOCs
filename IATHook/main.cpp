#include <iostream>
#include "IATHook.h"
#include "../Common/Constants.h"
#include "../Common/Utils.h"

int main(int argc, char** argv)
{
    char processName[MAX_LENGTH + 1];
    char targetModule[MAX_LENGTH + 1];
    char targetFunction[MAX_LENGTH + 1];
    char hookDll[MAX_LENGTH + 1];
    char hookFunction[MAX_LENGTH + 1];

    if (argc == 6) 
    {
        strncpy_s(processName, argv[1], MAX_LENGTH + 1);
        strncpy_s(targetModule, argv[2], MAX_LENGTH + 1);
        strncpy_s(targetFunction, argv[3], MAX_LENGTH + 1);
        strncpy_s(hookDll, argv[4], MAX_LENGTH + 1);
        strncpy_s(hookFunction, argv[5], MAX_LENGTH + 1);
    }
    else 
    {
        std::cout << "Process name:\n";
        std::cin.getline(processName, MAX_LENGTH + 1);
        std::cout << "Target module:\n";
        std::cin.getline(targetModule, MAX_LENGTH + 1);
        std::cout << "Target function :\n";
        std::cin.getline(targetFunction, MAX_LENGTH + 1);
        std::cout << "Hook dll:\n";
        std::cin.getline(hookDll, MAX_LENGTH + 1);
        std::cout << "Hook function :\n";
        std::cin.getline(hookFunction, MAX_LENGTH + 1);
    }

    if(!FileExists(hookDll))
    {
        std::cerr << "Could not open file hook dll " << hookDll << "\n";
        return 1;
    }

    Process* proc = new Process(processName);
    bool success = false;
    if (proc->Open())
    {
        if (InstallIATHook(proc, targetModule, targetFunction, hookDll, hookFunction))
        {
            std::cout << "IAT hook installed successfully!\n";
            success = true;
        }
        proc->Close();
    }

    delete proc;
    if (success)
        return 0;
    return 1;
}