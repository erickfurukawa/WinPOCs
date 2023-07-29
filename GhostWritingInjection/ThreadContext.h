#pragma once
#include <windows.h>
#include <memory>

/*
    Helper class to manage thread context registers in 32 and 64 bits.
*/
class ThreadContext
{
private:
    std::unique_ptr<BYTE[]> context;
    bool is32Bits = false;
public:
    ThreadContext(bool is32Bits);
    void* GetContextPtr();
    
    uintptr_t GetRip();
    uintptr_t GetRsp();

    uintptr_t GetRax();

    void SetRip(uintptr_t rip);
    void SetRsp(uintptr_t rsp);

    void SetRcx(uintptr_t rcx);
    void SetRdx(uintptr_t rdx);
    void SetRdi(uintptr_t rdi);
    void SetR9(uintptr_t r9);
    void SetR8(uintptr_t r8);
};