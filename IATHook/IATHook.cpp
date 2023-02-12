#include <iostream>
#include <windows.h>
#include "../Common/PE.h"
#include "../Common/Process.h"
#include "../DllInjection/DllInjection.h"
#include "IATHook.h"

bool InstallIATHook(Process* proc, char* targetModule, char* targetFunction, char* hookDll, char* hookFunction)
{
    bool success = false;
    PE* dll = new PE(hookDll);
    HANDLE hThread = InjectDll(proc, dll->filePath);
    int ptrSize = proc->is32Bits ? 4 : 8;
    if (hThread)
    {
        WaitForSingleObject(hThread, 3000);
        CloseHandle(hThread);

        // get hookFunction RVA
        MODULEENTRY32 meDll = proc->GetModule(dll->fileName);
        DWORD hookFunctionRVA = dll->GetExportRVA(hookFunction);
        uintptr_t hookAddr = reinterpret_cast<uintptr_t>(meDll.modBaseAddr + hookFunctionRVA);

        // get targetFunction IAT RVA
        PE* procPE = new PE(proc->mainModule.szExePath);
        DWORD targetFunctionRVA = procPE->GetImportRVA(targetModule, targetFunction);
        BYTE* IATaddr = proc->mainModule.modBaseAddr + targetFunctionRVA;
        delete procPE;

        if (hookFunctionRVA && targetFunctionRVA)
        {
            // overwrite IAT entry with hook address
            if (proc->WriteMemory(IATaddr, reinterpret_cast<BYTE*>(&hookAddr), ptrSize, true)) {
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

    delete dll;
    if (!success)
        std::cerr << "Could not install IAT hook\n";
    return success;
}
