#include "pch.h"
#include "DotnetDllLoader.h"
#include <iostream>
#include <metahost.h>
#pragma comment(lib, "mscoree.lib")

void StartTheDotNetRuntime();

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        StartTheDotNetRuntime();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

ICLRRuntimeHost* pClrRuntimeHost = NULL;

void StartTheDotNetRuntime()
{
    HRESULT hr;
    ICLRMetaHost* pMetaHost = NULL;
    ICLRRuntimeInfo* pRuntimeInfo = NULL;

    // build runtime
    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost));
    hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_PPV_ARGS(&pRuntimeInfo));
    hr = pRuntimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_PPV_ARGS(&pClrRuntimeHost));

    // start runtime
    hr = pClrRuntimeHost->Start();
    wprintf(L".Net runtime is loaded.\n");
}

// Loads a dotnet binary and runs a method
extern "C" __declspec(dllexport) void RunMethod(LoaderArgs * args)
{
    HRESULT hr;
    DWORD dwReturn = 0;

    hr = pClrRuntimeHost->ExecuteInDefaultAppDomain(
        reinterpret_cast<LPCWSTR>(args->assemblyPath), 
        reinterpret_cast<LPCWSTR>(args->typeName),
        reinterpret_cast<LPCWSTR>(args->methodName),
        reinterpret_cast<LPCWSTR>(args->argument),
        &dwReturn
    );
    std::cout << "HRESULT: 0x" << std::hex << (uintptr_t)hr << std::endl;
    std::cout << "dwReturn: 0x" << std::hex << (uintptr_t)dwReturn << std::endl;
}