#include "TokenPrivileges.h"
#include <iostream>
#include <memory>

std::string LUIDToString(LUID Luid)
{
    DWORD stringSize = 0;

    // get privilege name size
    LookupPrivilegeNameA(nullptr, &Luid, 0, &stringSize);

    auto buffer = std::make_unique<char[]>(stringSize);
    if (!LookupPrivilegeNameA(nullptr, &Luid, buffer.get(), &stringSize))
    {
        std::cerr << "LookupPrivilegeNameA error " << GetLastError() << std::endl;
        return std::string();
    }

    return std::string(buffer.get());
}

bool GetPrivilegeList(HANDLE procToken, std::vector<PrivilegeStatus>& privileges)
{
    bool success = true;
    DWORD returnSize = 0;

    // get required size for buffer and allocate
    GetTokenInformation(procToken, TOKEN_INFORMATION_CLASS::TokenPrivileges, nullptr, 0, &returnSize);
    auto tokenPrivsBuffer = std::make_unique<BYTE[]>(returnSize);
    TOKEN_PRIVILEGES* pTokenPrivs = reinterpret_cast<TOKEN_PRIVILEGES*>(tokenPrivsBuffer.get());

    // get privilege information
    if (GetTokenInformation(procToken, TOKEN_INFORMATION_CLASS::TokenPrivileges, pTokenPrivs, returnSize, &returnSize))
    {
        for (unsigned int i = 0; i < pTokenPrivs->PrivilegeCount; i++)
        {
            PrivilegeStatus thePriv = PrivilegeStatus();
            thePriv.name = LUIDToString(pTokenPrivs->Privileges[i].Luid);
            thePriv.enabled = pTokenPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED;
            privileges.push_back(thePriv);
        }
    }
    else
    {
        std::cerr << "GetTokenInformation error " << GetLastError() << std::endl;
        success = false;
    }
    return success;
}
