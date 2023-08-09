#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <windows.h>
#include "../../Common/Constants.h"
#include "../../Common/Utils.h"
#include "../../DllInjection/DllInjection.h"
#include "../DotnetDllLoader/DotnetDllLoader.h"
#include "DotnetDllInjection.h"

bool InjectDotnetDll(Process& proc, const char* dllPath, const char* methodName, const char* argument)
{
    PE dll(dllPath);
    return InjectDotnetDll(proc, dll, methodName, argument);
}

bool InjectDotnetDll(Process& proc, PE& dll, const char* methodName, const char* argument)
{
    bool success = false;
    char loaderPath[] = "dotnetDllLoader.dll";
    PE loaderDll = PE(loaderPath);
    PE injectDll = dll;
    BYTE* argsAddress = nullptr;

    if (proc.is32Bits != loaderDll.is32Bits)
    {
        std::cerr << "Target process and loader bitness are different!\n";
        return false;
    }

    // separate method name from typename
    wchar_t wstr[MAX_LENGTH + 1];
    ToWideString(methodName, wstr, MAX_LENGTH + 1);
    std::wstring fullMethodName(wstr);

    std::wistringstream f(fullMethodName);
    std::wstring token;
    while (std::getline(f, token, L'.')) {} // splits at '.'

    std::wstring wMethodName = token;
    std::wstring wTypeName = fullMethodName.substr(0, fullMethodName.size() - (wMethodName.size() + 1));;

    ToWideString(injectDll.filePath.c_str(), wstr, MAX_PATH + 1);
    std::wstring wInjectDllPath(wstr);
    ToWideString(argument, wstr, MAX_LENGTH + 1);
    std::wstring wArgument(wstr);

    // allocates memory for loader arguments
    std::cout << "Allocating memory for loader arguments...\n";
    size_t bytesNeeded = 0;
    bytesNeeded += sizeof(LoaderArgs);
    bytesNeeded += (wInjectDllPath.size() + 1) * sizeof(wchar_t);
    bytesNeeded += (wTypeName.size() + 1) * sizeof(wchar_t);
    bytesNeeded += (wMethodName.size() + 1) * sizeof(wchar_t);
    bytesNeeded += (wArgument.size() + 1) * sizeof(wchar_t);

    LoaderArgs loaderArgs = LoaderArgs();
    argsAddress = reinterpret_cast<BYTE*>(proc.AllocMemory(bytesNeeded));
    BYTE* currAddress = argsAddress + sizeof(LoaderArgs);

    // write argument strings
    loaderArgs.assemblyPath = reinterpret_cast<INT64>(currAddress);
    proc.WriteMemory(currAddress, (BYTE*)wInjectDllPath.c_str(), (wInjectDllPath.size() + 1) * sizeof(wchar_t));
    currAddress += (wInjectDllPath.size() + 1) * sizeof(wchar_t);

    loaderArgs.typeName = reinterpret_cast<INT64>(currAddress);
    proc.WriteMemory(currAddress, (BYTE*)wTypeName.c_str(), (wTypeName.size() + 1) * sizeof(wchar_t));
    currAddress += (wTypeName.size() + 1) * sizeof(wchar_t);

    loaderArgs.methodName = reinterpret_cast<INT64>(currAddress);
    proc.WriteMemory(currAddress, (BYTE*)wMethodName.c_str(), (wMethodName.size() + 1) * sizeof(wchar_t));
    currAddress += (wMethodName.size() + 1) * sizeof(wchar_t);

    loaderArgs.argument = reinterpret_cast<INT64>(currAddress);
    proc.WriteMemory(currAddress, (BYTE*)wArgument.c_str(), (wArgument.size() + 1) * sizeof(wchar_t));
    currAddress += (wArgument.size() + 1) * sizeof(wchar_t);

    // write loader args
    proc.WriteMemory(argsAddress, reinterpret_cast<BYTE*>(&loaderArgs), sizeof(LoaderArgs));
    std::cout << "Loader arguments allocated at 0x" << std::hex << (uintptr_t)argsAddress << "\n\n";

    std::cout << "Injecting loader...\n";
    HANDLE hThread = InjectDll(proc, loaderDll.filePath.c_str());
    if (hThread)
    {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        std::cout << "Loader dll has probably been injected successfully!\n\n";

        { // restrict variable scope because of goto
            // get address of StartDotNetRuntime function -------------
            MODULEENTRY32 meLoader = proc.GetModule(loaderDll.fileName.c_str());
            DWORD startRuntimeRVA = loaderDll.GetExportRVA("StartDotnetRuntime");
            void* startRuntimeAddr = meLoader.modBaseAddr + startRuntimeRVA;
            std::cout << "StartDotnetRuntime function at: 0x" << std::hex << (uintptr_t)startRuntimeAddr << "\n";

            // run StartDotNetRuntime function
            std::cout << "Running StartDotNetRuntime function...\n\n";
            hThread = CreateRemoteThread(proc.handle, nullptr, 0, (LPTHREAD_START_ROUTINE)startRuntimeAddr, 0, 0, nullptr);
            if (!hThread)
            {
                std::cerr << "Could not run StartDotNetRuntime function\n";
                goto cleanup;
            }
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);

            // get address of RunMethod function -------------
            DWORD injectRVA = loaderDll.GetExportRVA("RunMethod");
            void* injectAddr = meLoader.modBaseAddr + injectRVA;
            std::cout << "RunMethod function at: 0x" << std::hex << (uintptr_t)injectAddr << "\n";

            // run Inject function
            std::cout << "Running RunMethod function...\n\n";
            hThread = CreateRemoteThread(proc.handle, nullptr, 0, (LPTHREAD_START_ROUTINE)injectAddr, argsAddress, 0, nullptr);
            if (!hThread)
            {
                std::cerr << "Could not run RunMethod function\n";
                goto cleanup;
            }
            WaitForSingleObject(hThread, 3000);
            CloseHandle(hThread);
            success = true;
        }
    }
    else
    {
        std::cerr << "Could not inject loader into the target process\n";
    }

cleanup:
    if (argsAddress)
    {
        proc.FreeMemory(argsAddress);
    }

    return success;
}