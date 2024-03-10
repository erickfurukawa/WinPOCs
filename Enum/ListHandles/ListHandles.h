#pragma once
#include <phnt_windows.h>
#include <string>
#include <vector>

enum class ObjectType
{
    Unknown = 0,
    TmTm,
    Desktop,
    Process,
    EnergyTracker,
    RegistryTransaction,
    DebugObject,
    VRegConfigurationContext,
    DmaDomain,
    TpWorkerFactory,
    Adapter,
    Token,
    DxgkSharedResource,
    PsSiloContextPaged,
    NdisCmState,
    ActivityReference,
    PcwObject,
    WmiGuid,
    DmaAdapter,
    EtwRegistration,
    DxgkSharedBundleObject,
    Session,
    RawInputManager,
    Timer,
    Mutant,
    IRTimer,
    DxgkCurrentDxgProcessObject,
    IoCompletion,
    DxgkSharedProtectedSessionObject,
    DxgkSharedSyncObject,
    DxgkCompositionObject,
    WindowStation,
    Profile,
    File,
    Partition,
    Semaphore,
    PsSiloContextNonPaged,
    EtwConsumer,
    Composition,
    EtwSessionDemuxEntry,
    CoreMessaging,
    TmTx,
    SymbolicLink,
    FilterConnectionPort,
    Key,
    KeyedEvent,
    Callback,
    WaitCompletionPacket,
    UserApcReserve,
    Job,
    DxgkDisplayManagerObject,
    DxgkSharedSwapChainObject,
    Controller,
    IoCompletionReserve,
    Device,
    Directory,
    Section,
    TmEn,
    Thread,
    Type,
    FilterCommunicationPort,
    PowerRequest,
    TmRm,
    Event,
    ALPC_Port,
    Driver
};

typedef struct
{
    HANDLE remoteHandle;
    DWORD processId;
    DWORD grantedAccess;
    std::wstring handleType;
    std::wstring handleName;
} HandleInfo;

/*
    Returns a list of handles that could be duplicated.
    totalHandlesCount gets the number of total handles in the system.
*/
std::vector<HandleInfo> GetSystemHandles(PULONG totalHandlesCount);

std::wstring GetHandleName(HANDLE handle);

std::vector<std::wstring> GetAccessListFromMask(DWORD accessMask, std::wstring accessType);