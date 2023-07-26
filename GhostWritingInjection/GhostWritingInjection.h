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
    void WaitForLoop();
    void CallPushGadget(uintptr_t retAddress);
    void CallWriteGadget(uintptr_t what, uintptr_t where);
    void Detach();
};

bool GhostWritingInjection(DWORD threadID, PE& dll);