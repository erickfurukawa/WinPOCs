#pragma once
#include <windows.h>
#include <memory>

class GhostWriter
{
private:
    HANDLE threadHandle = nullptr;
    bool is32Bit = false;

    std::unique_ptr<BYTE[]> originalContext = {0};
    BYTE* loopGadgetAddr = nullptr;
    BYTE* writeGadgetAddr = nullptr;

public:
    GhostWriter(DWORD threadID, bool is32Bit);
    void SuspendThread();
    void ResumeThread();
    void SetLoopGadget(BYTE* address);
    void SetWriteGadget(BYTE* address);
    void WaitForLoop();
    void CallWriteGadget(uintptr_t what, uintptr_t where);
    void Detach();
};