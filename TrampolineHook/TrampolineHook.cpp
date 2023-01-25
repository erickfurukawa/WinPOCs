#include <iostream>
#include <windows.h>
#include "../Common/PE.h"
#include "../Common/Process.h"
#include "../DllInjection/DllInjection.h"
#include "include/capstone/capstone.h"
#include "TrampolineHook.h"

#define ORIGINAL_FUNC_POINTER_PREFIX "original_"

#define MAX_STOLEN_BYTES 30
#define NOP 0x90

#ifdef _WIN64
#define GATEWAY_SIZE 17
#define GATEWAY_BYTES "\x50\xC7\x04\x24\xEF\xBE\xAD\xDE\xC7\x44\x24\x04\xEF\xBE\xAD\xDE\xC3"
#define TRAMPOLINE_SIZE 12
#define TRAMPOLINE_BYTES "\x48\xB8\xEF\xBE\xAD\xDE\xEF\xBE\xAD\xDE\x50\xC3"
#else
// TODO x86 gateway defines
#endif

bool InstallTrampolineHook(Process* proc, char* targetModule, char* targetFunction, char* hookDll, char* hookFunction)
{
    bool success = false;
    PE* dll = new PE(hookDll);
    HANDLE hThread = InjectDll(proc, dll->filePath);
    BYTE* trampolineAddr = nullptr;
    DWORD oldProtect;

    if (hThread)
    {
        WaitForSingleObject(hThread, 1000);
        CloseHandle(hThread);

        // get hookFunction address
        MODULEENTRY32 meDll = proc->GetModule(dll->fileName);
        DWORD hookFunctionRVA = dll->GetExportRVA(hookFunction);
        uintptr_t hookAddr = reinterpret_cast<uintptr_t>(meDll.modBaseAddr) + hookFunctionRVA;

        // get trampolineAddrPtr export address
        std::string trampolineName = std::string(ORIGINAL_FUNC_POINTER_PREFIX) + targetFunction;
        DWORD trampolineAddrPtrRVA = dll->GetExportRVA(const_cast<char*>(trampolineName.c_str()));
        uintptr_t trampolineAddrPtr = reinterpret_cast<uintptr_t>(meDll.modBaseAddr) + trampolineAddrPtrRVA;

        // get targetFunction IAT address
        PE* procPE = new PE(proc->mainModule.szExePath);
        DWORD targetFunctionRVA = procPE->GetImportRVA(targetModule, targetFunction);
        uintptr_t IATaddr = reinterpret_cast<uintptr_t>(proc->mainModule.modBaseAddr) + targetFunctionRVA;
        delete procPE;

        // get targetFunction address
        uintptr_t targetFuncAddr;
        VirtualProtectEx(proc->handle, reinterpret_cast<LPVOID>(IATaddr), sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect);
        proc->ReadMemory(reinterpret_cast<LPCVOID>(IATaddr), reinterpret_cast<BYTE*>(&targetFuncAddr), sizeof(void*));
        VirtualProtectEx(proc->handle, reinterpret_cast<LPVOID>(IATaddr), sizeof(void*), oldProtect, &oldProtect);

        if (hookFunctionRVA && targetFunctionRVA && trampolineAddrPtrRVA)
        {
            // read first bytes of instructions from target function
            BYTE code[MAX_STOLEN_BYTES];
            proc->ReadMemory(reinterpret_cast<BYTE*>(targetFuncAddr), code, MAX_STOLEN_BYTES);

            // use capstone to find the number of stolen bytes
            csh handle;
            cs_insn* insn;
            size_t count;

            int stolenBytesSize = 0;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK)
            {
                count = cs_disasm(handle, reinterpret_cast<uint8_t*>(code), MAX_STOLEN_BYTES, 0x1000, 0, &insn);
                if (count > 0)
                {
                    size_t j;
                    for (j = 0; j < count; j++)
                    {
                        stolenBytesSize += insn[j].size;
                        if (stolenBytesSize >= GATEWAY_SIZE)
                            break;
                    }
                    cs_free(insn, count);
                }
                cs_close(&handle);
            }

            if (stolenBytesSize < GATEWAY_SIZE)
            { 
                std::cerr << "Could not determine the number of stolen bytes\n";
                goto cleanup;
            }
            // alloc memory for trampoline
            trampolineAddr = reinterpret_cast<BYTE*>(proc->AllocMemory(stolenBytesSize + TRAMPOLINE_SIZE));

            // write trampoline
            BYTE* trampoline = new BYTE[stolenBytesSize + TRAMPOLINE_SIZE];
            uintptr_t origFuncPlusStolenBytes = targetFuncAddr + stolenBytesSize;
            proc->ReadMemory(reinterpret_cast<BYTE*>(targetFuncAddr), trampoline, stolenBytesSize); // read stolen bytes
#ifdef _WIN64
            memcpy(trampoline + stolenBytesSize, TRAMPOLINE_BYTES, TRAMPOLINE_SIZE); // trampoline
            memcpy(trampoline + stolenBytesSize + 2, &origFuncPlusStolenBytes, sizeof(void*)); // original func addr
#else
            //TODO: x86
#endif
            proc->WriteMemory(trampolineAddr, trampoline, stolenBytesSize + TRAMPOLINE_SIZE);
            delete[] trampoline;

            // write trampolineAddr to trampolineAddrPtr
            DWORD oldProtect;

            VirtualProtectEx(proc->handle, reinterpret_cast<LPVOID>(trampolineAddrPtr), sizeof(void*), PAGE_EXECUTE_READWRITE ,&oldProtect);
            proc->WriteMemory(reinterpret_cast<BYTE*>(trampolineAddrPtr), (BYTE*) &trampolineAddr, sizeof(void*));
            VirtualProtectEx(proc->handle, reinterpret_cast<LPVOID>(trampolineAddrPtr), sizeof(void*), oldProtect, &oldProtect);

            // write gateway + nops
            int extraNops = stolenBytesSize - GATEWAY_SIZE;
            BYTE* gateway = new BYTE[GATEWAY_SIZE + extraNops];
#ifdef _WIN64
            memcpy(gateway, GATEWAY_BYTES, GATEWAY_SIZE); // gateway: jump to hook
            memcpy(gateway + 4, reinterpret_cast<BYTE*>(&hookAddr), sizeof(DWORD)); // hook function address low
            memcpy(gateway + 12, (reinterpret_cast<BYTE*>(&hookAddr) + sizeof(DWORD)), sizeof(DWORD)); // hook function address high
            memset(gateway + GATEWAY_SIZE, NOP, extraNops); // nops
#else
            //TODO: x86
#endif
            VirtualProtectEx(proc->handle, reinterpret_cast<LPVOID>(targetFuncAddr), sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect);
            proc->WriteMemory(reinterpret_cast<BYTE*>(targetFuncAddr), gateway, GATEWAY_SIZE + extraNops);
            VirtualProtectEx(proc->handle, reinterpret_cast<LPVOID>(targetFuncAddr), sizeof(void*), oldProtect, &oldProtect);
            delete[] gateway;
            success = true;
        }
        else
        {
            std::cerr << "Could not get valid RVAs for " << targetFunction << " or " << hookFunction <<  " or " << trampolineName << "\n";
        }
    }

cleanup:
    delete dll;
    if (!success)
    {
        std::cerr << "Could not install Inline hook\n";
        if (trampolineAddr)
        {
            proc->FreeMemory(trampolineAddr);
        }
    }
    return success;
}
