#include <iostream>
#include "TokenPrivileges.h"
#include "../Common/Process.h"
#include "../Common/Utils.h"
#include "../Common/Constants.h"

bool ListPrivs(Process& proc);
bool EnablePrivs(Process& proc);

/*
    TokenPrivileges.exe - List current process privileges
    TokenPrivileges.exe list - List current process privileges
    TokenPrivileges.exe enable - Enable current process privileges

    TokenPrivileges.exe list procName - List privileges of another process
    TokenPrivileges.exe enable procName - Enable privileges of another process

    Caveat: running in cmd.exe does not enable own privileges because it spawns a child process.
    Maybe add option to enable parent process privileges?
*/
int main(int argc, char** argv)
{
    int option = 0; // 0: list / 1: enable
    Process proc = Process(GetCurrentProcessId());
    if (argc == 3)
    {
        proc = Process(argv[2]);
    }

    if (argc == 1) // default option: list
    {
        option = 0;
    }
    else
    {
        std::string command = std::string(argv[1]);

        if (command == "enable")
        {
            option = 1;
        }
        else // list
        {
            option = 0;
        }
    }
    
    bool success = false;
    if (proc.Open(PROCESS_QUERY_LIMITED_INFORMATION) && proc.OpenProcessToken(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY))
    {
        if (option == 0)
        {
            success = ListPrivs(proc);
            if (success)
            {
                std::cout << "Process privileges listed successfully!\n";
            }
        }
        else
        {
            success = EnablePrivs(proc);
            if (success)
            {
                std::cout << "Process privileges enabled successfully!\n";
            }
        }
        proc.CloseProcessToken();
        proc.Close();
    }
    else
    {
        std::cerr << "Could not open target process or process token\n";
    }

    if (success)
        return 0;
    return 1;
}

bool ListPrivs(Process& proc)
{
    std::vector<PrivilegeStatus> privilegeList;
    if (GetPrivilegeList(proc.token, privilegeList))
    {
        for (PrivilegeStatus priv : privilegeList)
        {
            if (priv.enabled)
            {
                std::cout << "Enabled  - " << priv.name << std::endl;
            }
            else
            {
                std::cout << "Disabled - " << priv.name << std::endl;
            }
        }
        return true;
    }
    else
    {
        std::cerr << "GetPrivilegeList error\n";
    }
    return false;
}

bool EnablePrivs(Process& proc)
{
    if (EnableAllPrivileges(proc.token))
    {
        return true;
    }
    else
    {
        std::cerr << "EnableAllPrivileges error\n";
    }
    return false;
}