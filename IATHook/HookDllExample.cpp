#include "pch.h"
#include <iostream>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) int __cdecl _stricmp_hook(const char* str1, const char* str2)
{
    // hook logic
    std::cout << "Hook called with arguments\n" << str1 << "\n" << str2 << "\n";

    // call original and return
    return _stricmp(str1, str2);
}