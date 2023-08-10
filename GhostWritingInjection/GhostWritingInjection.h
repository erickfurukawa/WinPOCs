#pragma once
#include <windows.h>
#include <memory>
#include "../Common/PE.h"

class GhostWriter
{
private:
    HANDLE threadHandle = nullptr;

public:
    bool is32Bits = false;
    /*
        an address that contains the address to the loop gadget.
        used by write gadget to return to the loop.
    */
    BYTE* loopGadgetPtrAddr = nullptr;
    BYTE* loopGadgetAddr = nullptr;
    BYTE* pushGadgetAddr = nullptr;
    BYTE* writeGadgetAddr = nullptr;

    GhostWriter(DWORD threadID, bool is32Bits);
    HANDLE GetThreadHandle();
    bool SuspendThread();
    bool ResumeThread();
    void GetContext(void* context);
    void SetContext(void* context);
    void WriteBytes(const BYTE* buffer, size_t bufferSize, uintptr_t where);
    void WaitForLoop();
    void CallFunctionAt(BYTE* address);
    // makes thread loop
    void CallPushGadget();
    // write-what-where. stack pointer must contain loop gadget address
    void CallWriteGadget(uintptr_t what, uintptr_t where);
};

bool GhostWritingInjection(DWORD threadID, PE& dll);