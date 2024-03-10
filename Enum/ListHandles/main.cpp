#include <iostream>
#include "ListHandles.h"

std::wstring GetAccessString(DWORD grantedAccess, std::wstring accessType)
{
    std::vector<std::wstring> accessList = GetAccessListFromMask(grantedAccess, accessType);
    if (accessList.size() > 0)
    {
        std::wstring accessStr = {};
        for (std::wstring& access : accessList)
        {
            accessStr += access + L" | ";
        }
        return accessStr.substr(0, accessStr.size() - 3);
    }
    return L"[no access]";
}

int main(int argc, char** argv)
{
    DWORD pid = 0;

    if (argc == 2)
    {
        pid = atoi(argv[1]);
    }

    unsigned long allHandlesCount;
    auto handles = GetSystemHandles(&allHandlesCount);
    std::cout << "Total system handle count: " << allHandlesCount << std::endl;
    for (auto& handle : handles)
    {
        if (pid != 0 && handle.processId != pid)
        {
            continue;
        }
        std::wcout << L"PID: " << handle.processId << L" Type: " << handle.handleType << L" Name: " << handle.handleName << std::endl;
        std::wcout << GetAccessString(handle.grantedAccess, handle.handleType) << std::endl << std::endl;
    }
    return 0;
}