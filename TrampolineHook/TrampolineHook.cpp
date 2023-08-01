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
#define MIN_JMP_RANGE(ADDR) ADDR + MININT32 + 5
#define MAX_JMP_RANGE(ADDR) ADDR + MAXINT32 + 5

#ifdef _WIN64
#define ABS_JMP_SIZE 17
// TODO: This apparently triggers CET. change to jmp r11 or something.
#define ABS_JMP_BYTES "\x50\xC7\x04\x24\xEF\xBE\xAD\xDE\xC7\x44\x24\x04\xEF\xBE\xAD\xDE\xC3"
#define REL_JMP_SIZE 5
#define REL_JMP_BYTES "\xE9\xEF\xBE\xAD\xDE"
#else
// TODO x86 ABS_JMP_BYTES defines
#endif

namespace // anonymous namespace for utility functions
{
#ifdef _WIN64
    void BuildAbsoluteJump(BYTE* buffer, uintptr_t absAddr)
    {
        memcpy(buffer, ABS_JMP_BYTES, ABS_JMP_SIZE);
        memcpy(buffer + 4, reinterpret_cast<BYTE*>(&absAddr), sizeof(DWORD)); // absAddr low
        memcpy(buffer + 12, reinterpret_cast<BYTE*>(&absAddr) + sizeof(DWORD), sizeof(DWORD)); // absAddr high
    };

    bool BuildRelativeJump(BYTE* buffer, uintptr_t currAddr, uintptr_t targetAddr)
    {
        if (targetAddr < MAX_JMP_RANGE(currAddr) && targetAddr > MIN_JMP_RANGE(currAddr))
        {
            INT32 relAddr = targetAddr - currAddr - 5;
            memcpy(buffer, REL_JMP_BYTES, REL_JMP_SIZE);
            memcpy(buffer + 1, reinterpret_cast<BYTE*>(&relAddr), sizeof(INT32)); // rel addr
            return true;
        }
        return false;
    };
#else
    // TODO x86
#endif
}

bool InstallTrampolineHook(Process& proc, char* targetModule, char* targetFunction, char* hookDll, char* hookFunction)
{
    bool success = false;
    PE dll = PE(hookDll);
    BYTE* trampolineAddr = nullptr;
    BYTE* relayAddr = nullptr;

    HANDLE hThread = InjectDll(proc, dll.filePath);
    if (hThread)
    {
        WaitForSingleObject(hThread, 3000);
        CloseHandle(hThread);

        // get hookFunction address
        MODULEENTRY32 meDll = proc.GetModule(dll.fileName);
        DWORD hookFunctionRVA = dll.GetExportRVA(hookFunction);
        uintptr_t hookAddr = reinterpret_cast<uintptr_t>(meDll.modBaseAddr) + hookFunctionRVA;

        // get trampolineAddrPtr export address
        std::string trampolineName = std::string(ORIGINAL_FUNC_POINTER_PREFIX) + targetFunction;
        DWORD trampolineAddrPtrRVA = dll.GetExportRVA(const_cast<char*>(trampolineName.c_str()));
        uintptr_t trampolineAddrPtr = reinterpret_cast<uintptr_t>(meDll.modBaseAddr) + trampolineAddrPtrRVA;

        // TODO: is it really necessary to read from IAT? 
        // get targetFunction IAT address
        PE procPE = PE(proc.GetMainModule().szExePath);
        DWORD targetFunctionRVA = procPE.GetImportRVA(targetModule, targetFunction);
        uintptr_t IATaddr = reinterpret_cast<uintptr_t>(proc.GetMainModule().modBaseAddr) + targetFunctionRVA;

        // get targetFunction address
        uintptr_t targetFuncAddr;
        proc.ReadMemory(reinterpret_cast<LPCVOID>(IATaddr), reinterpret_cast<BYTE*>(&targetFuncAddr), sizeof(void*));

        if (hookFunctionRVA && targetFunctionRVA && trampolineAddrPtrRVA)
        {
            // read first bytes of instructions from target function
            BYTE code[MAX_STOLEN_BYTES];
            proc.ReadMemory(reinterpret_cast<BYTE*>(targetFuncAddr), code, MAX_STOLEN_BYTES);

            // use capstone to find the number of stolen bytes
            csh handle;
            cs_insn* insn;
            size_t count;

            int stolenBytesSize = 0;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK)
            {
                cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
                count = cs_disasm(handle, reinterpret_cast<uint8_t*>(code), MAX_STOLEN_BYTES, 0x1000, 0, &insn);
                if (count > 0)
                {
                    size_t j;
                    for (j = 0; j < count; j++)
                    {
                        stolenBytesSize += insn[j].size;
                        if (stolenBytesSize >= REL_JMP_SIZE)
                            break;
                    }
                    cs_free(insn, count);
                }
                cs_close(&handle);
            }

            if (stolenBytesSize < REL_JMP_SIZE)
            { 
                std::cerr << "Could not determine the number of stolen bytes\n";
                goto cleanup;
            }

            // alloc memory for relay in reachable memory
            relayAddr = reinterpret_cast<BYTE*>(
                    proc.AllocMemory(ABS_JMP_SIZE, 
                        reinterpret_cast<LPVOID>(MIN_JMP_RANGE(targetFuncAddr)),
                        reinterpret_cast<LPVOID>(MAX_JMP_RANGE(targetFuncAddr))
                    )
                );

            BYTE relay[ABS_JMP_SIZE];
            BuildAbsoluteJump(relay, hookAddr); // relay -> hookFunction
            proc.WriteMemory(relayAddr, relay, ABS_JMP_SIZE); // write relay

            // alloc memory for trampoline
            trampolineAddr = reinterpret_cast<BYTE*>(proc.AllocMemory(stolenBytesSize + ABS_JMP_SIZE));
            BYTE* trampoline = new BYTE[stolenBytesSize + ABS_JMP_SIZE];
            uintptr_t origFuncPlusStolenBytes = targetFuncAddr + stolenBytesSize;
            proc.ReadMemory(reinterpret_cast<BYTE*>(targetFuncAddr), trampoline, stolenBytesSize); // read stolen bytes
            BuildAbsoluteJump(trampoline + stolenBytesSize, origFuncPlusStolenBytes); // add jmp to original function
            proc.WriteMemory(trampolineAddr, trampoline, stolenBytesSize + ABS_JMP_SIZE);
            delete[] trampoline;

            // write trampolineAddr to trampolineAddrPtr
            proc.WriteMemory(reinterpret_cast<BYTE*>(trampolineAddrPtr), (BYTE*) &trampolineAddr, sizeof(void*), true);

            // write stub + nops
            int extraNops = stolenBytesSize - REL_JMP_SIZE;
            BYTE* hookStub = new BYTE[REL_JMP_SIZE + extraNops];
            BuildRelativeJump(hookStub, targetFuncAddr, reinterpret_cast<uintptr_t>(relayAddr)); // add hook: original -> relay
            memset(hookStub + REL_JMP_SIZE, NOP, extraNops); // nops
            proc.WriteMemory(reinterpret_cast<BYTE*>(targetFuncAddr), hookStub, REL_JMP_SIZE + extraNops, true);
            delete[] hookStub;

            success = true;
        }
        else
        {
            std::cerr << "Could not get valid RVAs for " << targetFunction << " or " << hookFunction <<  " or " << trampolineName << "\n";
        }
    }

cleanup:
    if (!success)
    {
        std::cerr << "Could not install Inline hook\n";
        if (trampolineAddr)
        {
            proc.FreeMemory(trampolineAddr);
        }
        if (relayAddr)
        {
            proc.FreeMemory(relayAddr);
        }
    }
    return success;
}
