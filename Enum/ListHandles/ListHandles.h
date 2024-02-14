#pragma once
#include <phnt_windows.h>
#include <string>
#include <vector>

typedef struct
{
    HANDLE remoteHandle;
    DWORD processId;
    std::wstring handleType;
    std::wstring handleName;
} HandleInfo;

/*
    Returns a list of handles that could be queried.
    totalHandlesCount gets the number of total handles in the system.
*/
std::vector<HandleInfo> GetSystemHandles(PULONG totalHandlesCount);