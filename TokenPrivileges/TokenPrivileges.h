#pragma once

#include <windows.h>
#include <vector>
#include <string>

typedef struct _PrivilegeStatus
{
    std::string name = std::string();
    bool enabled = false;
} PrivilegeStatus;

std::string LUIDToString(LUID Luid);

bool GetPrivilegeList(HANDLE procToken, std::vector<PrivilegeStatus>& privileges);

// TODO
bool EnableAllPrivileges(HANDLE procToken);
