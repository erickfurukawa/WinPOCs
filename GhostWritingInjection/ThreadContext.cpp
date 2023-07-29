#include "ThreadContext.h"

ThreadContext::ThreadContext(bool is32Bits)
{
    this->is32Bits = is32Bits;

    unsigned int contextSize = max(sizeof(CONTEXT), sizeof(WOW64_CONTEXT));
    this->context = std::make_unique<BYTE[]>(contextSize);

    if (is32Bits)
    {
        reinterpret_cast<PWOW64_CONTEXT>(this->context.get())->ContextFlags = CONTEXT_ALL;
    }
    else
    {
        reinterpret_cast<PCONTEXT>(this->context.get())->ContextFlags = CONTEXT_ALL;
    }
}

void* ThreadContext::GetContextPtr()
{
    return this->context.get();
}

uintptr_t ThreadContext::GetRip()
{
    if (this->is32Bits)
    {
        return reinterpret_cast<PWOW64_CONTEXT>(this->context.get())->Eip;
    }
    else
    {
        return reinterpret_cast<LPCONTEXT>(this->context.get())->Rip;
    }
}

uintptr_t ThreadContext::GetRsp()
{
    if (this->is32Bits)
    {
        return reinterpret_cast<PWOW64_CONTEXT>(this->context.get())->Esp;
    }
    else
    {
        return reinterpret_cast<LPCONTEXT>(this->context.get())->Rsp;
    }
}

uintptr_t ThreadContext::GetRax()
{
    if (this->is32Bits)
    {
        return reinterpret_cast<PWOW64_CONTEXT>(this->context.get())->Eax;
    }
    else
    {
        return reinterpret_cast<LPCONTEXT>(this->context.get())->Rax;
    }
}

void ThreadContext::SetRip(uintptr_t rip)
{
    if (this->is32Bits)
    {
        reinterpret_cast<PWOW64_CONTEXT>(this->context.get())->Eip = static_cast<DWORD>(rip);
    }
    else
    {
        reinterpret_cast<PCONTEXT>(this->context.get())->Rip = rip;
    }
}

void ThreadContext::SetRsp(uintptr_t rsp)
{
    if (this->is32Bits)
    {
        reinterpret_cast<PWOW64_CONTEXT>(this->context.get())->Esp = static_cast<DWORD>(rsp);
    }
    else
    {
        reinterpret_cast<PCONTEXT>(this->context.get())->Rsp = rsp;
    }
}


void ThreadContext::SetRcx(uintptr_t rcx)
{
    if (this->is32Bits)
    {
        reinterpret_cast<PWOW64_CONTEXT>(this->context.get())->Ecx = static_cast<DWORD>(rcx);
    }
    else
    {
        reinterpret_cast<PCONTEXT>(this->context.get())->Rcx = rcx;
    }
}

void ThreadContext::SetRdx(uintptr_t rdx)
{
    if (this->is32Bits)
    {
        reinterpret_cast<PWOW64_CONTEXT>(this->context.get())->Edx = static_cast<DWORD>(rdx);
    }
    else
    {
        reinterpret_cast<PCONTEXT>(this->context.get())->Rdx = rdx;
    }
}

void ThreadContext::SetRdi(uintptr_t rdi)
{
    if (this->is32Bits)
    {
        reinterpret_cast<PWOW64_CONTEXT>(this->context.get())->Edi = static_cast<DWORD>(rdi);
    }
    else
    {
        reinterpret_cast<PCONTEXT>(this->context.get())->Rdi = rdi;
    }
}

void ThreadContext::SetR9(uintptr_t r9)
{
    if (this->is32Bits)
    {
        
    }
    else
    {
        reinterpret_cast<PCONTEXT>(this->context.get())->R9 = r9;
    }
}

void ThreadContext::SetR8(uintptr_t r8)
{
    if (this->is32Bits)
    {

    }
    else
    {
        reinterpret_cast<PCONTEXT>(this->context.get())->R8 = r8;
    }
}
