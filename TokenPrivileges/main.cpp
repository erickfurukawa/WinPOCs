#include <iostream>
#include "TokenPrivileges.h"
#include "../Common/Process.h"
#include "../Common/Utils.h"
#include "../Common/Constants.h"

/*
    TokenPrivileges.exe - List current process privileges
    TokenPrivileges.exe procName - List privileges of another process
*/
int main(int argc, char** argv)
{
    int option = 0;
    Process proc = Process(GetCurrentProcessId());

    if (argc == 1)
    {
        option = 0;
    }
    else if (argc == 2)
    {
        proc = Process(argv[1]);
    }
    
    bool success = true;
    if (proc.Open(PROCESS_QUERY_LIMITED_INFORMATION) && proc.OpenProcessToken(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY))
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
            success = true;
        }
        else
        {
            std::cerr << "GetPrivilegeList error\n";
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
