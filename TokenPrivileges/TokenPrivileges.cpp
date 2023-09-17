#include "TokenPrivileges.h"
#include <iostream>
#include <memory>

namespace
{
    IntegrityLevel IntegrityLevelValueToEnum(DWORD integrityLevel)
    {
        if (integrityLevel >= SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
        {
            return IntegrityLevel::Protected;
        }
        if (integrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
        {
            return IntegrityLevel::System;
        }
        if (integrityLevel >= SECURITY_MANDATORY_HIGH_RID)
        {
            return IntegrityLevel::High;
        }
        if (integrityLevel >= SECURITY_MANDATORY_MEDIUM_PLUS_RID)
        {
            return IntegrityLevel::MediumPlus;
        }
        if (integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID)
        {
            return IntegrityLevel::Medium;
        }
        if (integrityLevel >= SECURITY_MANDATORY_LOW_RID)
        {
            return IntegrityLevel::Low;
        }
        return IntegrityLevel::Untrusted;
    }
}

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

bool EnableAllPrivileges(HANDLE procToken)
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
            pTokenPrivs->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
        }
        if (!AdjustTokenPrivileges(procToken, false, pTokenPrivs, 0, nullptr, nullptr))
        {
            std::cerr << "AdjustTokenPrivileges error " << GetLastError() << std::endl;
            success = false;
        }
    }
    else
    {
        std::cerr << "GetTokenInformation error " << GetLastError() << std::endl;
        success = false;
    }
    return success;
}

IntegrityLevel GetIntegrityLevel(HANDLE token)
{
    std::string integrityLevel = "";
    DWORD returnSize = 0;

    // get required size for buffer and allocate
    GetTokenInformation(token, TOKEN_INFORMATION_CLASS::TokenIntegrityLevel, nullptr, 0, &returnSize);
    auto tokenLabelBuffer = std::make_unique<BYTE[]>(returnSize);
    TOKEN_MANDATORY_LABEL* pTokenLabel = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(tokenLabelBuffer.get());

    // get integrity level information
    if (GetTokenInformation(token, TOKEN_INFORMATION_CLASS::TokenIntegrityLevel, pTokenLabel, returnSize, &returnSize))
    {
        DWORD dwIntegrityLevel = *GetSidSubAuthority(pTokenLabel->Label.Sid, static_cast<DWORD>((*GetSidSubAuthorityCount(pTokenLabel->Label.Sid)) - 1u));
        return IntegrityLevelValueToEnum(dwIntegrityLevel);
    }
    else
    {
        std::cerr << "GetTokenInformation error " << GetLastError() << std::endl;
    }
    return IntegrityLevel::Unknown;
}

bool ImpersonateToken(HANDLE token)
{
    HANDLE dupToken;
    bool success = false;

    if (DuplicateToken(token, SECURITY_IMPERSONATION_LEVEL::SecurityImpersonation, &dupToken))
    {
        if (SetThreadToken(NULL, dupToken))
        {
            success = true;
        }
        else
        {
            std::cerr << "SetThreadToken error " << GetLastError() << std::endl;
        }
        CloseHandle(dupToken);
    }
    else
    {
        std::cerr << "DuplicateToken error " << GetLastError() << std::endl;
    }
    return success;
}