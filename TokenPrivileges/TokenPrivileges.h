#pragma once

#include <windows.h>
#include <vector>
#include <string>

enum class IntegrityLevel
{
    Unknown = 0,
    AppContainer,
    Untrusted,
    Low,
    Medium,
    MediumPlus,
    High,
    System,
    Protected
};

typedef struct _PrivilegeStatus
{
    std::string name = std::string();
    bool enabled = false;
} PrivilegeStatus;

std::string LUIDToString(LUID Luid);

bool GetPrivilegeList(HANDLE procToken, std::vector<PrivilegeStatus>& privileges);

bool EnableAllPrivileges(HANDLE procToken);

IntegrityLevel GetIntegrityLevel(HANDLE token);

bool ImpersonateToken(HANDLE token);

std::wstring IntegrityLevelToString(IntegrityLevel il);