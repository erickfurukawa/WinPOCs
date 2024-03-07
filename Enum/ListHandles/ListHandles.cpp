#include "ListHandles.h"
#include "../../Common/Utils.h"
#include <phnt.h>
#include <memory>
#include <iostream>

namespace
{
    typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION
    {
        UNICODE_STRING TypeName;
        ULONG Reserved[22];
    } PUBLIC_OBJECT_TYPE_INFORMATION, * PPUBLIC_OBJECT_TYPE_INFORMATION;

    typedef struct
    {
        HANDLE handle;
        std::wstring pipeName;
    } GetPipeNameWorkerArgs;

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

    HANDLE DuplicateRemoteHandle(HANDLE remoteHandle, DWORD handleOwnerPid)
    {
        HANDLE localHandle = nullptr;
        HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handleOwnerPid);
        if (hProc)
        {
            NTSTATUS status = NtDuplicateObject(hProc, remoteHandle, GetCurrentProcess(), &localHandle, 0, 0, DUPLICATE_SAME_ACCESS);
            if (status == STATUS_SUCCESS)
            {
                ULONG returnLength;
                auto buffer = std::make_unique<BYTE[]>(0x1000);
                status = NtQueryObject(localHandle, OBJECT_INFORMATION_CLASS::ObjectTypeInformation, buffer.get(), 0x1000, &returnLength);
                if (status != STATUS_SUCCESS)
                {
                    localHandle = NULL;
                }
            }
            CloseHandle(hProc);
        }
        return localHandle;
    }

    std::wstring GetHandleType(HANDLE handle)
    {
        std::wstring handleType = L"unknown";
        if (handle)
        {
            ULONG returnLength;
            auto buffer = std::make_unique<BYTE[]>(0x1000);
            NTSTATUS status = NtQueryObject(handle, OBJECT_INFORMATION_CLASS::ObjectTypeInformation, buffer.get(), 0x1000, &returnLength);
            if (status == STATUS_SUCCESS)
            {
                handleType = std::wstring(reinterpret_cast<PPUBLIC_OBJECT_TYPE_INFORMATION>(buffer.get())->TypeName.Buffer);
            }
        }
        return handleType;
    }
    
    DWORD WINAPI GetPipeNameWorker(GetPipeNameWorkerArgs* args)
    {
        ULONG returnLength = 0;
        BYTE buffer[0x1000] = {};
        if (GetFileInformationByHandleEx(args->handle, FILE_INFO_BY_HANDLE_CLASS::FileNameInfo, buffer, 0x1000))
        {
            args->pipeName = L"\\Device\\NamedPipe" + std::wstring(reinterpret_cast<FILE_NAME_INFO*>(buffer)->FileName);
        }
        else
        {
            args->pipeName = L"[unknown]";
        }
        return 0;
    }

    std::wstring GetFileHandleName(HANDLE handle)
    {
        std::wstring fileName = L"[unknown file]";
        ULONG returnLength = 0;
        int size = 0x500;
        auto buffer = std::make_unique<wchar_t[]>(size);
        bool success = false;

        // named pipe
        GetPipeNameWorkerArgs getHandleNameArgs = {};
        HANDLE threadHandle;
        DWORD status = 0, threadId = 0;

        switch (GetFileType(handle))
        {
        case(FILE_TYPE_CHAR):
            fileName = std::wstring(L"[unknown char]");
            break;
        case(FILE_TYPE_DISK):
            if (NtQueryObject(handle, OBJECT_INFORMATION_CLASS::ObjectNameInformation, buffer.get(), size*sizeof(wchar_t), &returnLength) == STATUS_SUCCESS)
            {
                fileName = NtPathToCanonical(std::wstring(reinterpret_cast<POBJECT_NAME_INFORMATION>(buffer.get())->Name.Buffer));
            }
            else
            {
                fileName = L"[unknown disk]";
            }
            break;
        case(FILE_TYPE_PIPE):
            getHandleNameArgs.handle = handle;
            threadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GetPipeNameWorker, (LPVOID) &getHandleNameArgs, 0, &threadId);
            if (threadHandle != NULL)
            {
                status = WaitForSingleObject(threadHandle, 30);
                if (status == WAIT_OBJECT_0)
                {
                    success = true;
                    fileName = getHandleNameArgs.pipeName;
                }
                else
                {
                    TerminateThread(threadHandle, 0);
                }
                CloseHandle(threadHandle);
            }
            if (!success)
            {
                fileName = std::wstring(L"[unknown pipe]");
            }
            break;
        case(FILE_TYPE_REMOTE):
            fileName = std::wstring(L"[unknown remote]");
            break;
        default:
            if (NtQueryObject(handle, OBJECT_INFORMATION_CLASS::ObjectNameInformation, buffer.get(), 0x1000, &returnLength) == STATUS_SUCCESS)
            {
                fileName = std::wstring(reinterpret_cast<POBJECT_NAME_INFORMATION>(buffer.get())->Name.Buffer);
            }
            else
            {
                fileName = std::wstring(L"[unknown file]");
            }
            break;
        }
        return fileName;
    }
}

std::wstring GetHandleName(HANDLE handle)
{
    std::wstring handleName = L"unknown";
    std::wstring handleType = GetHandleType(handle);
    if (handleType == L"File")
    {
        return GetFileHandleName(handle);
    }
    else  // TODO: other handle types
    {

    }
    return handleName;
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
        HANDLE localHandle = DuplicateRemoteHandle(reinterpret_cast<HANDLE>(handleInfoEx.HandleValue), static_cast<DWORD>(handleInfoEx.UniqueProcessId));
        if (localHandle)
        {
            HandleInfo handleEntry{ 0 };
            handleEntry.remoteHandle = reinterpret_cast<HANDLE>(handleInfoEx.HandleValue);
            handleEntry.processId = static_cast<DWORD>(handleInfoEx.UniqueProcessId);
            handleEntry.handleType = GetHandleType(localHandle);
            handleEntry.handleName = GetHandleName(localHandle);
            handles.push_back(handleEntry);
            CloseHandle(localHandle);
        }
    }
    return handles;
}