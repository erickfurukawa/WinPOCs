#include "ListHandles.h"
#include <phnt.h>
#include <memory>
#include <iostream>

namespace
{
    typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
        UNICODE_STRING TypeName;
        ULONG Reserved[22];
    } PUBLIC_OBJECT_TYPE_INFORMATION, * PPUBLIC_OBJECT_TYPE_INFORMATION;

    std::wstring GetHandleType(HANDLE remoteHandle, DWORD handleOwnerPid)
    {
        // opens process, duplicates handle, and queries handle info
        std::wstring type;
        HANDLE self = OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());
        HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handleOwnerPid);
        if (hProc)
        {
            HANDLE localHandle;
            NTSTATUS status = NtDuplicateObject(hProc, remoteHandle, self, &localHandle, 0, 0, DUPLICATE_SAME_ACCESS);
            if (status == STATUS_SUCCESS)
            {
                ULONG returnLength;
                auto buffer = std::make_unique<BYTE[]>(0x1000);
                status = NtQueryObject(localHandle, OBJECT_INFORMATION_CLASS::ObjectTypeInformation, buffer.get(), 0x1000, &returnLength);
                if (status == STATUS_SUCCESS)
                {
                    type = std::wstring(reinterpret_cast<PPUBLIC_OBJECT_TYPE_INFORMATION>(buffer.get())->TypeName.Buffer);
                }
                
                CloseHandle(localHandle);
            }
            CloseHandle(hProc);
        }
        return type;
    }
}

std::vector<HandleInfo> GetSystemHandles(PULONG totalHandlesCount)
{
    ULONG returnSize = 0;
    NTSTATUS status = 0;
    ULONG bufferSize = 0x1000;
    auto systemHandlesBuffer = std::make_unique<BYTE[]>(bufferSize);

    // Get all system handles
    while ((status = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemExtendedHandleInformation, systemHandlesBuffer.get(), bufferSize, &returnSize))
        == STATUS_INFO_LENGTH_MISMATCH)
    {
        bufferSize *= 2;
        systemHandlesBuffer = std::make_unique<BYTE[]>(bufferSize);
    }
    if (status != STATUS_SUCCESS)
    {
        std::cerr << "NtQuerySystemInformation error 0x" << std::hex << status << std::endl;
    }

    // loop through handles
    std::vector<HandleInfo> handles{ 0 };
    PSYSTEM_HANDLE_INFORMATION_EX pSystemHandles = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(systemHandlesBuffer.get());
    if (totalHandlesCount != nullptr)
    {
        *totalHandlesCount = static_cast<ULONG>(pSystemHandles->NumberOfHandles);
    }
    for (ULONG i = 0; i < pSystemHandles->NumberOfHandles; i++)
    {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handleInfoEx = pSystemHandles->Handles[i];
        std::wstring type = GetHandleType(reinterpret_cast<HANDLE>(handleInfoEx.HandleValue), static_cast<DWORD>(handleInfoEx.UniqueProcessId));
        if (!type.empty())
        {
            HandleInfo handleEntry{ 0 };
            handleEntry.remoteHandle = reinterpret_cast<HANDLE>(handleInfoEx.HandleValue);
            handleEntry.processId = static_cast<DWORD>(handleInfoEx.UniqueProcessId);
            handleEntry.handleType = type;
            handles.push_back(handleEntry);
        }
    }
    return handles;
}