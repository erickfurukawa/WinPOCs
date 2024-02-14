#include "ListHandles.h"
#include "../../Common/Utils.h"
#include <phnt.h>
#include <memory>
#include <iostream>

namespace
{
    typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
        UNICODE_STRING TypeName;
        ULONG Reserved[22];
    } PUBLIC_OBJECT_TYPE_INFORMATION, * PPUBLIC_OBJECT_TYPE_INFORMATION;

    std::wstring NtPathToCanonical(std::wstring ntPath)
    {
        std::wstring ntPathLower = ntPath;
        LowerString(ntPathLower);

        DWORD dwDriveMask = GetLogicalDrives();
        for (int i = 0; i < 26; i++)
        {
            if (dwDriveMask & (1 << i))
            {
                wchar_t driveNameBuffer[MAX_PATH];
                wchar_t drive[3] = {0};
                drive[0] = L'A' + i;
                drive[1] = L':';
                if (QueryDosDeviceW(drive, driveNameBuffer, MAX_PATH) != 0)
                {
                    std::wstring driveName = std::wstring(driveNameBuffer);
                    LowerString(driveName);

                    if (ntPathLower.find(driveName) != std::string::npos)
                    {
                        return drive + ntPath.substr(driveName.size(), ntPath.size() - driveName.size());
                    }
                }
            }
        }
        return L"";
    }

    std::wstring HandleToFileName(HANDLE handle)
    {
        ULONG returnLength = 0;
        int size = 0x500;
        auto buffer = std::make_unique<wchar_t[]>(size);

        switch (GetFileType(handle))
        {
        case(FILE_TYPE_CHAR):
            return std::wstring(L"[unknown char]");
            break;
        case(FILE_TYPE_DISK):
            if (NtQueryObject(handle, OBJECT_INFORMATION_CLASS::ObjectNameInformation, buffer.get(), 0x1000, &returnLength) == STATUS_SUCCESS)
            {
                return NtPathToCanonical(std::wstring(reinterpret_cast<POBJECT_NAME_INFORMATION>(buffer.get())->Name.Buffer));
            }
            return std::wstring(L"[unknown disk]");
            break;
        case(FILE_TYPE_PIPE):
                return std::wstring(L"[unknown pipe]");
            break;
        case(FILE_TYPE_REMOTE):
            return std::wstring(L"[unknown remote]");
            break;
        default:
            if (NtQueryObject(handle, OBJECT_INFORMATION_CLASS::ObjectNameInformation, buffer.get(), 0x1000, &returnLength) == STATUS_SUCCESS)
            {
                return std::wstring(reinterpret_cast<POBJECT_NAME_INFORMATION>(buffer.get())->Name.Buffer);
            }
            return std::wstring(L"[unknown]");
            break;
        }
    }

    bool GetHandleInfo(HANDLE remoteHandle, DWORD handleOwnerPid, std::wstring& handleType, std::wstring& handleName)
    {
        bool success = false;
        // opens process, duplicates handle, and queries handle info
        HANDLE self = GetCurrentProcess();
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
                    success = true; // TODO: REMOVE AFTER ADDING ALL HANDLE NAMES
                    handleType = std::wstring(reinterpret_cast<PPUBLIC_OBJECT_TYPE_INFORMATION>(buffer.get())->TypeName.Buffer);
                    
                    if (handleType == L"File")
                    {
                        handleName = HandleToFileName(localHandle);
                    }
                }
                CloseHandle(localHandle);
            }
            CloseHandle(hProc);
        }
        return success;
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
        std::wstring handleType, handleName;
        if (GetHandleInfo(reinterpret_cast<HANDLE>(handleInfoEx.HandleValue), static_cast<DWORD>(handleInfoEx.UniqueProcessId), handleType, handleName))
        {
            HandleInfo handleEntry{ 0 };
            handleEntry.remoteHandle = reinterpret_cast<HANDLE>(handleInfoEx.HandleValue);
            handleEntry.processId = static_cast<DWORD>(handleInfoEx.UniqueProcessId);
            handleEntry.handleType = handleType;
            handleEntry.handleName = handleName;
            handles.push_back(handleEntry);
        }
    }
    return handles;
}