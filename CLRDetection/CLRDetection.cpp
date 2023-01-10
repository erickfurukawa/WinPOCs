#include "CLRDetection.h"
#include <iostream>

void EnumerateRuntimes(IEnumUnknown** runtime)
{
    IUnknown* enumRuntime = nullptr;
    ICLRRuntimeInfo* runtimeInfo = nullptr;
    WCHAR frameworkName[2048];
    DWORD bytes = 1024;

    while ((*runtime)->Next(1, &enumRuntime, 0) == S_OK)
    {
        if (enumRuntime->QueryInterface<ICLRRuntimeInfo>(&runtimeInfo) == S_OK)
        {
            if (runtimeInfo != NULL)
            {
                runtimeInfo->GetVersionString(frameworkName, &bytes);
                std::wcout << frameworkName << std::endl;
                runtimeInfo->Release();
            }
        }
    }
}
