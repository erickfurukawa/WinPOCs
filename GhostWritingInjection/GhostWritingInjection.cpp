#include <iostream>
#include "GhostWritingInjection.h"
#include "../Common/Utils.h"

GhostWriter::GhostWriter(DWORD threadID, bool is32Bit)
{
    this->threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, threadID);
    if (!this->threadHandle)
    {
        ThrowException(std::string("GhostWriter: OpenThread error ") + std::to_string(GetLastError()));
    }
    this->is32Bit = is32Bit;

    // save thread context to restore later
    this->SuspendThread();
    if (is32Bit)
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