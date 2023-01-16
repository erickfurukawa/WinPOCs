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
    if (hThread)
    {
        WaitForSingleObject(hThread, 1000);
        CloseHandle(hThread);

        // get hookFunction RVA
        MODULEENTRY32 meDll = proc->GetModule(dll->fileName);
        DWORD hookFunctionRVA = dll->GetExportRVA(hookFunction);
        uintptr_t hookAddr = (uintptr_t)meDll.modBaseAddr + hookFunctionRVA;

        // get targetFunction IAT RVA
        PE* procPE = new PE(proc->mainModule.szExePath);
        DWORD targetFunctionRVA = procPE->GetImportRVA(targetModule, targetFunction);
        uintptr_t IATaddr = (uintptr_t)proc->mainModule.modBaseAddr + targetFunctionRVA;

        delete procPE;

        if (hookFunctionRVA && targetFunctionRVA)
        {
            // overwrite IAT entry with hook address
            DWORD oldProtect;
            if (VirtualProtectEx(proc->handle, (void*)IATaddr, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                if (proc->WriteMemory((void*)IATaddr, (BYTE*)&hookAddr, sizeof(void*))) {
                    success = true;
                }
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
