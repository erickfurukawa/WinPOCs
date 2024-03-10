#include "ListHandles.h"
#include "../../Common/Utils.h"
#include <phnt.h>
#include <memory>
#include <iostream>
#include <psapi.h>
#include <map>

namespace // Handle access -----------------------------------------------------------------
{
    std::map<DWORD, std::wstring> GenericAndStandardAccessMap = {
        {DELETE, L"DELETE"},
        {READ_CONTROL, L"READ_CONTROL"},
        {WRITE_DAC, L"WRITE_DAC"},
        {WRITE_OWNER, L"WRITE_OWNER"},
        {SYNCHRONIZE, L"SYNCHRONIZE"},
        {1 << 21, L"STANDARD_21"},
        {1 << 22, L"STANDARD_22"},
        {1 << 23, L"STANDARD_23"},
        {ACCESS_SYSTEM_SECURITY, L"ACCESS_SYSTEM_SECURITY"},
        {MAXIMUM_ALLOWED, L"MAXIMUM_ALLOWED"},
        {1 << 26, L"RESERVED_26"},
        {1 << 27, L"RESERVED_27"},
        {GENERIC_ALL, L"GENERIC_ALL"},
        {GENERIC_EXECUTE, L"GENERIC_EXECUTE"},
        {GENERIC_WRITE, L"GENERIC_WRITE"},
        {GENERIC_READ, L"GENERIC_READ"}
    };

    std::map<DWORD, std::wstring> DefaultSpecificAccessMap = {
        {1 << 0, L"SPECIFIC_0"},
        {1 << 1, L"SPECIFIC_1"},
        {1 << 2, L"SPECIFIC_2"},
        {1 << 3, L"SPECIFIC_3"},
        {1 << 4, L"SPECIFIC_4"},
        {1 << 5, L"SPECIFIC_5"},
        {1 << 6, L"SPECIFIC_6"},
        {1 << 7, L"SPECIFIC_7"},
        {1 << 8, L"SPECIFIC_8"},
        {1 << 9, L"SPECIFIC_9"},
        {1 << 10, L"SPECIFIC_10"},
        {1 << 11, L"SPECIFIC_11"},
        {1 << 12, L"SPECIFIC_12"},
        {1 << 13, L"SPECIFIC_13"},
        {1 << 14, L"SPECIFIC_14"},
        {1 << 15, L"SPECIFIC_15"}
    };

    std::map<DWORD, std::wstring> ProcessAccessMap = {
        {PROCESS_TERMINATE, L"PROCESS_TERMINATE"},
        {PROCESS_CREATE_THREAD, L"PROCESS_CREATE_THREAD"},
        {PROCESS_SET_SESSIONID, L"PROCESS_SET_SESSIONID"},
        {PROCESS_VM_OPERATION, L"PROCESS_VM_OPERATION"},
        {PROCESS_VM_READ, L"PROCESS_VM_READ"},
        {PROCESS_VM_WRITE, L"PROCESS_VM_WRITE"},
        {PROCESS_DUP_HANDLE, L"PROCESS_DUP_HANDLE"},
        {PROCESS_CREATE_PROCESS, L"PROCESS_CREATE_PROCESS"},
        {PROCESS_SET_QUOTA, L"PROCESS_SET_QUOTA"},
        {PROCESS_SET_INFORMATION, L"PROCESS_SET_INFORMATION"},
        {PROCESS_QUERY_INFORMATION, L"PROCESS_QUERY_INFORMATION"},
        {PROCESS_SUSPEND_RESUME, L"PROCESS_SUSPEND_RESUME"},
        {PROCESS_QUERY_LIMITED_INFORMATION, L"PROCESS_QUERY_LIMITED_INFORMATION"},
        {PROCESS_SET_LIMITED_INFORMATION, L"PROCESS_SET_LIMITED_INFORMATION"}
    };

    std::map<DWORD, std::wstring> FileAccessMap = {
        {FILE_READ_DATA, L"FILE_READ_DATA"}, // or FILE_LIST_DIRECTORY
        {FILE_WRITE_DATA, L"FILE_WRITE_DATA"}, // or FILE_ADD_FILE
        {FILE_APPEND_DATA, L"FILE_APPEND_DATA"}, // or FILE_ADD_SUBDIRECTORY or FILE_CREATE_PIPE_INSTANCE
        {FILE_READ_EA, L"FILE_READ_EA"},
        {FILE_WRITE_EA, L"FILE_WRITE_EA"},
        {FILE_EXECUTE, L"FILE_EXECUTE"}, // or FILE_TRAVERSE
        {FILE_DELETE_CHILD, L"FILE_DELETE_CHILD"}, // directory
        {FILE_READ_ATTRIBUTES, L"FILE_READ_ATTRIBUTES"},
        {FILE_WRITE_ATTRIBUTES, L"FILE_WRITE_ATTRIBUTES"}
    };

    std::map<DWORD, std::wstring> TokenAccessMap = {
        {TOKEN_ASSIGN_PRIMARY, L"TOKEN_ASSIGN_PRIMARY"},
        {TOKEN_DUPLICATE, L"TOKEN_DUPLICATE"},
        {TOKEN_IMPERSONATE, L"TOKEN_IMPERSONATE"},
        {TOKEN_QUERY, L"TOKEN_QUERY"},
        {TOKEN_QUERY_SOURCE, L"TOKEN_QUERY_SOURCE"},
        {TOKEN_ADJUST_PRIVILEGES, L"TOKEN_ADJUST_PRIVILEGES"},
        {TOKEN_ADJUST_GROUPS, L"TOKEN_ADJUST_GROUPS"},
        {TOKEN_ADJUST_DEFAULT, L"TOKEN_ADJUST_DEFAULT"},
        {TOKEN_ADJUST_SESSIONID, L"TOKEN_ADJUST_SESSIONID"}
    };

    std::map<DWORD, std::wstring> ThreadAccessMap = {
        {THREAD_TERMINATE, L"THREAD_TERMINATE"},
        {THREAD_SUSPEND_RESUME, L"THREAD_SUSPEND_RESUME"},
        {THREAD_GET_CONTEXT, L"THREAD_GET_CONTEXT"},
        {THREAD_SET_CONTEXT, L"THREAD_SET_CONTEXT"},
        {THREAD_QUERY_INFORMATION, L"THREAD_QUERY_INFORMATION"},
        {THREAD_SET_INFORMATION, L"THREAD_SET_INFORMATION"},
        {THREAD_SET_THREAD_TOKEN, L"THREAD_SET_THREAD_TOKEN"},
        {THREAD_IMPERSONATE, L"THREAD_IMPERSONATE"},
        {THREAD_DIRECT_IMPERSONATION, L"THREAD_DIRECT_IMPERSONATION"},
        {THREAD_SET_LIMITED_INFORMATION, L"THREAD_SET_LIMITED_INFORMATION"},
        {THREAD_QUERY_LIMITED_INFORMATION, L"THREAD_QUERY_LIMITED_INFORMATION"}
    };

    std::map<DWORD, std::wstring> KeyAccessMap = {
        {KEY_QUERY_VALUE , L"KEY_QUERY_VALUE "},
        {KEY_SET_VALUE, L"KEY_SET_VALUE"},
        {KEY_CREATE_SUB_KEY, L"KEY_CREATE_SUB_KEY"},
        {KEY_ENUMERATE_SUB_KEYS, L"KEY_ENUMERATE_SUB_KEYS"},
        {KEY_NOTIFY, L"KEY_NOTIFY"},
        {KEY_CREATE_LINK, L"KEY_CREATE_LINK"},
        {KEY_WOW64_32KEY, L"KEY_WOW64_32KEY"},
        {KEY_WOW64_64KEY, L"KEY_WOW64_64KEY"}
    };
}

namespace
{
    // or OBJECT_TYPE_INFORMATION
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

    ObjectType ObjectTypeFromString(std::wstring type)
    {
        static std::map<std::wstring, ObjectType> objTypeMap = {
            {L"TmTm", ObjectType::TmTm},
            {L"Desktop", ObjectType::Desktop},
            {L"Process", ObjectType::Process},
            {L"EnergyTracker", ObjectType::EnergyTracker},
            {L"RegistryTransaction", ObjectType::RegistryTransaction},
            {L"DebugObject", ObjectType::DebugObject},
            {L"VRegConfigurationContext", ObjectType::VRegConfigurationContext},
            {L"DmaDomain", ObjectType::DmaDomain},
            {L"TpWorkerFactory", ObjectType::TpWorkerFactory},
            {L"Adapter", ObjectType::Adapter},
            {L"Token", ObjectType::Token},
            {L"DxgkSharedResource", ObjectType::DxgkSharedResource},
            {L"PsSiloContextPaged", ObjectType::PsSiloContextPaged},
            {L"NdisCmState", ObjectType::NdisCmState},
            {L"ActivityReference", ObjectType::ActivityReference},
            {L"PcwObject", ObjectType::PcwObject},
            {L"WmiGuid", ObjectType::WmiGuid},
            {L"DmaAdapter", ObjectType::DmaAdapter},
            {L"EtwRegistration", ObjectType::EtwRegistration},
            {L"DxgkSharedBundleObject", ObjectType::DxgkSharedBundleObject},
            {L"Session", ObjectType::Session},
            {L"RawInputManager", ObjectType::RawInputManager},
            {L"Timer", ObjectType::Timer},
            {L"Mutant", ObjectType::Mutant},
            {L"IRTimer", ObjectType::IRTimer},
            {L"DxgkCurrentDxgProcessObject", ObjectType::DxgkCurrentDxgProcessObject},
            {L"IoCompletion", ObjectType::IoCompletion},
            {L"DxgkSharedProtectedSessionObject", ObjectType::DxgkSharedProtectedSessionObject},
            {L"DxgkSharedSyncObject", ObjectType::DxgkSharedSyncObject},
            {L"DxgkCompositionObject", ObjectType::DxgkCompositionObject},
            {L"WindowStation", ObjectType::WindowStation},
            {L"Profile", ObjectType::Profile},
            {L"File", ObjectType::File},
            {L"Partition", ObjectType::Partition},
            {L"Semaphore", ObjectType::Semaphore},
            {L"PsSiloContextNonPaged", ObjectType::PsSiloContextNonPaged},
            {L"EtwConsumer", ObjectType::EtwConsumer},
            {L"Composition", ObjectType::Composition},
            {L"EtwSessionDemuxEntry", ObjectType::EtwSessionDemuxEntry},
            {L"CoreMessaging", ObjectType::CoreMessaging},
            {L"TmTx", ObjectType::TmTx},
            {L"SymbolicLink", ObjectType::SymbolicLink},
            {L"FilterConnectionPort", ObjectType::FilterConnectionPort},
            {L"Key", ObjectType::Key},
            {L"KeyedEvent", ObjectType::KeyedEvent},
            {L"Callback", ObjectType::Callback},
            {L"WaitCompletionPacket", ObjectType::WaitCompletionPacket},
            {L"UserApcReserve", ObjectType::UserApcReserve},
            {L"Job", ObjectType::Job},
            {L"DxgkDisplayManagerObject", ObjectType::DxgkDisplayManagerObject},
            {L"DxgkSharedSwapChainObject", ObjectType::DxgkSharedSwapChainObject},
            {L"Controller", ObjectType::Controller},
            {L"IoCompletionReserve", ObjectType::IoCompletionReserve},
            {L"Device", ObjectType::Device},
            {L"Directory", ObjectType::Directory},
            {L"Section", ObjectType::Section},
            {L"TmEn", ObjectType::TmEn},
            {L"Thread", ObjectType::Thread},
            {L"Type", ObjectType::Type},
            {L"FilterCommunicationPort", ObjectType::FilterCommunicationPort},
            {L"PowerRequest", ObjectType::PowerRequest},
            {L"TmRm", ObjectType::TmRm},
            {L"Event", ObjectType::Event},
            {L"ALPC Port", ObjectType::ALPC_Port},
            {L"Driver", ObjectType::Driver}
        };

        if (objTypeMap.find(type) == objTypeMap.end())
        {
            std::wcerr << type << std::endl;
            ThrowException("Unknown object type!");
        }
        return objTypeMap[type];
    }

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
            if (status != STATUS_SUCCESS)
            {
                localHandle = nullptr;
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
            BYTE buffer[0x400] = {0};
            NTSTATUS status = NtQueryObject(handle, OBJECT_INFORMATION_CLASS::ObjectTypeInformation, buffer, 0x400, &returnLength);
            if (status == STATUS_SUCCESS)
            {
                handleType = std::wstring(reinterpret_cast<PPUBLIC_OBJECT_TYPE_INFORMATION>(buffer)->TypeName.Buffer);
            }
        }
        return handleType;
    }
    
    DWORD WINAPI GetPipeNameWorker(GetPipeNameWorkerArgs* args)
    {
        ULONG returnLength = 0;
        BYTE buffer[0x400] = {0};
        if (GetFileInformationByHandleEx(args->handle, FILE_INFO_BY_HANDLE_CLASS::FileNameInfo, buffer, 0x400))
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
        BYTE buffer[0x400] = {0};
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
            if (NtQueryObject(handle, OBJECT_INFORMATION_CLASS::ObjectNameInformation, buffer, 0x400, &returnLength) == STATUS_SUCCESS)
            {
                fileName = NtPathToCanonical(std::wstring(reinterpret_cast<POBJECT_NAME_INFORMATION>(buffer)->Name.Buffer));
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
            if (NtQueryObject(handle, OBJECT_INFORMATION_CLASS::ObjectNameInformation, buffer, 0x400, &returnLength) == STATUS_SUCCESS)
            {
                fileName = std::wstring(reinterpret_cast<POBJECT_NAME_INFORMATION>(buffer)->Name.Buffer);
            }
            else
            {
                fileName = std::wstring(L"[unknown file]");
            }
            break;
        }
        return fileName;
    }

    std::wstring GetProcessHandleName(HANDLE handle)
    {
        std::wstring processName = L"[unknown process]";
        HANDLE queryHandle = nullptr;
        
        if (DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), &queryHandle, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0))
        {
            wchar_t buffer[0x1000] = {};
            if (GetProcessImageFileNameW(queryHandle, buffer, 0x1000) > 0)
            {
                processName = NtPathToCanonical(std::wstring(buffer));
            }
            CloseHandle(queryHandle);
        }
        return processName;
    }
}

std::wstring GetHandleName(HANDLE handle)
{
    std::wstring handleName = L"[unknown]";
    std::wstring handleType = GetHandleType(handle);
    if (handleType == L"File")
    {
        return GetFileHandleName(handle);
    }
    else if (handleType == L"Process")
    {
        return GetProcessHandleName(handle);
    }
    else  // TODO: other handle types
    {

    }
    return handleName;
}

std::vector<std::wstring> GetAccessListFromMask(DWORD accessMask, std::wstring accessType)
{
    std::vector<std::wstring> accessList = {};
    for (int i = 16; i < 32; i++)
    {
        DWORD acessValue = (1 << i);
        if (acessValue & accessMask)
        {
            accessList.push_back(GenericAndStandardAccessMap[acessValue]);
        }
    }
    std::map<DWORD, std::wstring>* specificAccessMap;
    switch (ObjectTypeFromString(accessType))
    {
    case (ObjectType::Process):
        specificAccessMap = &ProcessAccessMap;
        break;
    case (ObjectType::File):
        specificAccessMap = &FileAccessMap;
        break;
    case (ObjectType::Token):
        specificAccessMap = &TokenAccessMap;
        break;
    case (ObjectType::Thread):
        specificAccessMap = &ThreadAccessMap;
        break;
    case (ObjectType::Key):
        specificAccessMap = &KeyAccessMap;
        break;
    default: // TODO: other specific accesses
        specificAccessMap = &DefaultSpecificAccessMap;
        break;
    }

    for (int i = 0; i < 16; i++)
    {
        DWORD acessValue = (1 << i);
        if ((acessValue & accessMask))
        {
            if ((specificAccessMap->find(acessValue) != specificAccessMap->end()))
            {
                accessList.push_back((*specificAccessMap)[acessValue]);
            }
            else
            {
                accessList.push_back(DefaultSpecificAccessMap[acessValue]);
            }
        }
    }
    return accessList;
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
            handleEntry.grantedAccess = handleInfoEx.GrantedAccess;
            handleEntry.handleType = GetHandleType(localHandle);
            handleEntry.handleName = GetHandleName(localHandle);
            handles.push_back(handleEntry);
            CloseHandle(localHandle);
        }
    }
    return handles;
}