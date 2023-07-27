#pragma once
#include <windows.h>
#include <memory>
#include "../Common/PE.h"

class GhostWriter
{
private:
    HANDLE threadHandle = nullptr;
    bool is32Bits = false;

    BYTE* loopGadgetAddr = nullptr;
    BYTE* pushGadgetAddr = nullptr;
    BYTE* writeGadgetAddr = nullptr;

public:
    GhostWriter(DWORD threadID);
    HANDLE GetThreadHandle();
    bool SuspendThread();
    bool ResumeThread();
    void GetContext(void* context);
    void SetContext(void* context);
    void SetLoopGadget(BYTE* address);
    void SetPushGadget(BYTE* address);
    void SetWriteGadget(BYTE* address);
    void WriteBytes(BYTE* buffer, size_t bufferSize, uintptr_t where);
    void WaitForLoop();
    // makes thread loop
    void CallPushGadget();
    // write-what-where. stack pointer must contain loop gadget address
    void CallWriteGadget(uintptr_t what, uintptr_t where);
};

bool GhostWritingInjection(DWORD threadID, PE& dll);