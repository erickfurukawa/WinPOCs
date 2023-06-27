#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <windows.h>
#include "../../Common/Process.h"
#include "../../Common/Constants.h"
#include "../../Common/Utils.h"
#include "../../Common/PE.h"
#include "../../DllInjection/DllInjection.h"
#include "../DotnetDllLoader/DotnetDllLoader.h"

int main(int argc, char** argv)
{
    bool success = false;
    char processName[MAX_LENGTH + 1];
    char dotnetDllPath[MAX_PATH + 1];
    char methodName[MAX_LENGTH + 1];
    char argument[MAX_LENGTH + 1];

    char loaderPath[] = "dotnetDllLoader.dll";

    if (argc == 5)
    {
        strncpy_s(processName, argv[1], MAX_LENGTH + 1);
        strncpy_s(dotnetDllPath, argv[2], MAX_PATH + 1);
        strncpy_s(methodName, argv[3], MAX_LENGTH + 1);
        strncpy_s(argument, argv[4], MAX_LENGTH + 1);
    }
    else
    {
        std::cout << "Process name:\n";
        std::cin.getline(processName, MAX_LENGTH + 1);
        std::cout << "Dotnet dll path:\n";
        std::cin.getline(dotnetDllPath, MAX_PATH + 1);
        std::cout << "Method to run:\n";
        std::cin.getline(methodName, MAX_LENGTH + 1);
        std::cout << "String argument:\n";
        std::cin.getline(argument, MAX_LENGTH + 1);
    }

    PE* loaderDll = nullptr;
    PE* injectDll = nullptr;
    Process* proc = nullptr;
    BYTE* argsAddress = nullptr;

    { // restrict variable scope because of goto
        loaderDll = new PE(loaderPath);
        injectDll = new PE(dotnetDllPath);
        proc = new Process(processName);
        if (!proc->Open())
        {
            std::cerr << "Could not open target process\n";
            goto cleanup;
        }

        if (proc->is32Bits != loaderDll->is32Bits)
        {
            std::cerr << "Target process and loader bitness are different!\n";
            goto cleanup;
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

        ToWideString(injectDll->filePath, wstr, MAX_PATH + 1);
        std::wstring wInjectDllPath(wstr);
        ToWideString(argument, wstr, MAX_LENGTH + 1);
        std::wstring wArgument(wstr);

        wprintf(L"Method '%ls' from type '%ls' from dll '%ls' will be called with arguments '%ls'.\n\n",
            wMethodName.c_str(), wTypeName.c_str(), wInjectDllPath.c_str(), wArgument.c_str());

        // allocates memory for loader arguments
        std::cout << "Allocating memory for loader arguments...\n";
        size_t bytesNeeded = 0;
        bytesNeeded += sizeof(LoaderArgs);
        bytesNeeded += (wInjectDllPath.size() + 1) * sizeof(wchar_t);
        bytesNeeded += (wTypeName.size() + 1) * sizeof(wchar_t);
        bytesNeeded += (wMethodName.size() + 1) * sizeof(wchar_t);
        bytesNeeded += (wArgument.size() + 1) * sizeof(wchar_t);

        LoaderArgs loaderArgs;
        argsAddress = reinterpret_cast<BYTE*>(proc->AllocMemory(bytesNeeded));
        BYTE* currAddress = argsAddress + sizeof(LoaderArgs);

        // write argument strings
        loaderArgs.assemblyPath = reinterpret_cast<INT64>(currAddress);
        proc->WriteMemory(currAddress, (BYTE*)wInjectDllPath.c_str(), (wInjectDllPath.size() + 1) * sizeof(wchar_t));
        currAddress += (wInjectDllPath.size() + 1) * sizeof(wchar_t);

        loaderArgs.typeName = reinterpret_cast<INT64>(currAddress);
        proc->WriteMemory(currAddress, (BYTE*)wTypeName.c_str(), (wTypeName.size() + 1) * sizeof(wchar_t));
        currAddress += (wTypeName.size() + 1) * sizeof(wchar_t);

        loaderArgs.methodName = reinterpret_cast<INT64>(currAddress);
        proc->WriteMemory(currAddress, (BYTE*)wMethodName.c_str(), (wMethodName.size() + 1) * sizeof(wchar_t));
        currAddress += (wMethodName.size() + 1) * sizeof(wchar_t);

        loaderArgs.argument = reinterpret_cast<INT64>(currAddress);
        proc->WriteMemory(currAddress, (BYTE*)wArgument.c_str(), (wArgument.size() + 1) * sizeof(wchar_t));
        currAddress += (wArgument.size() + 1) * sizeof(wchar_t);

        // write loader args
        proc->WriteMemory(argsAddress, reinterpret_cast<BYTE*>(&loaderArgs), sizeof(LoaderArgs));

        std::cout << "Loader arguments allocated at 0x" << std::hex << (uintptr_t)argsAddress << "\n\n";

        std::cout << "Injecting loader...\n";
        HANDLE hThread = InjectDll(proc, loaderDll->filePath);
        if (!hThread)
        {
            std::cerr << "Could not inject loader into the target process\n";
            goto cleanup;
        }
        WaitForSingleObject(hThread, 3000);
        CloseHandle(hThread);
        std::cout << "Loader dll has probably been injected successfully!\n\n";

        // get address of StartDotNetRuntime method -------------
        std::cout << "Finding address of StartDotnetRuntime method...\n";
        MODULEENTRY32 meLoader = proc->GetModule(loaderDll->fileName);
        DWORD startRuntimeRVA = loaderDll->GetExportRVA("StartDotnetRuntime");
        void* startRuntimeAddr = meLoader.modBaseAddr + startRuntimeRVA;
        std::cout << "StartDotnetRuntime method at: 0x" << std::hex << (uintptr_t)startRuntimeAddr << "\n";

        // run StartDotNetRuntime method
        std::cout << "Running StartDotNetRuntime method...\n\n";
        hThread = CreateRemoteThread(proc->handle, nullptr, 0, (LPTHREAD_START_ROUTINE)startRuntimeAddr, 0, 0, nullptr);
        if (!hThread)
        {
            std::cerr << "Could not run StartDotNetRuntime method\n";
            goto cleanup;
        }
        WaitForSingleObject(hThread, 3000);
        CloseHandle(hThread);

        // get address of RunMethod method -------------
        std::cout << "Finding address of RunMethod method...\n";
        DWORD injectRVA = loaderDll->GetExportRVA("RunMethod");
        void* injectAddr = meLoader.modBaseAddr + injectRVA;
        std::cout << "RunMethod method at: 0x" << std::hex << (uintptr_t)injectAddr << "\n";

        // run Inject method
        std::cout << "Running RunMethod method...\n\n";
        hThread = CreateRemoteThread(proc->handle, nullptr, 0, (LPTHREAD_START_ROUTINE)injectAddr, argsAddress, 0, nullptr);
        if (!hThread)
        {
            std::cerr << "Could not run RunMethod method\n";
            goto cleanup;
        }
        WaitForSingleObject(hThread, 3000);
        CloseHandle(hThread);
        std::cout << "Dotnet dll has probably been injected successfully!\n\n";
        success = true;
    }

cleanup:
    if (proc->handle)
    {
        if (argsAddress)
        {
            proc->FreeMemory(argsAddress);
        }
        proc->Close();
    }
    delete proc;
    delete loaderDll;
    delete injectDll;

    if (success)
    {
        return 0;
    }
    return 1;
}