#include <iostream>
#include <windows.h>
#include "../Common/PE.h"
#include "../Common/Process.h"
#include "../DllInjection/DllInjection.h"
#include "IATHook.h"

bool InstallIATHook(Process& proc, char* targetModule, char* targetFunction, char* hookDll, char* hookFunction)
{
    bool success = false;
    PE dll = PE(hookDll);
    HANDLE hThread = InjectDll(proc, dll);
    int ptrSize = proc.is32Bits ? 4 : 8;
    if (hThread)
    {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);

        // get hookFunction address
        MODULEENTRY32 meDll = proc.GetModule(dll.fileName);
        DWORD hookFunctionRVA = dll.GetExportRVA(hookFunction);
        uintptr_t hookAddr = reinterpret_cast<uintptr_t>(meDll.modBaseAddr + hookFunctionRVA);

        // get targetFunction IAT address
        PE procPE = PE(proc.mainModule.szExePath);
        DWORD targetFunctionRVA = procPE.GetImportRVA(targetModule, targetFunction);
        BYTE* IATaddr = proc.mainModule.modBaseAddr + targetFunctionRVA;

        if (hookFunctionRVA && targetFunctionRVA)
        {
            // overwrite IAT entry with hook address
            if (proc.WriteMemory(IATaddr, reinterpret_cast<BYTE*>(&hookAddr), ptrSize, true)) {
                success = true;
            }
            if (!success)
            {
                std::cerr << "Could not write to IAT\n";
            }
        }
        else
        {
            std::cerr << "Could not get valid RVAs for " << targetFunction << " or " << hookFunction << "\n";
        }
    }

    if (!success)
        std::cerr << "Could not install IAT hook\n";
    return success;
}
