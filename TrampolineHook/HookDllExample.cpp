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

using f_stricmp = int(__cdecl*)(const char* str1, const char* str2);

// this is where a reference to the original function will be stored.
// it is required for each function that will be hooked.
extern "C" __declspec(dllexport) uintptr_t original__stricmp = 0xdeadbeef;

// the hook function
extern "C" __declspec(dllexport) int __cdecl _stricmp_hook(const char* str1, const char* str2)
{
    f_stricmp original_func = reinterpret_cast<f_stricmp>(original__stricmp);

    // ---------- hook logic ---------- 
    std::cout << "Hook called with arguments\n" << str1 << "\n" << str2 << "\n";
    std::cout << "original func: " << std::hex << (uintptr_t)original_func << "\n";

    //return original_func(str1, str2);
    return 0;
}