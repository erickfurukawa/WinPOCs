#pragma once

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

DWORD GetPid(char* procName);

void* AllocMem(HANDLE hProc, size_t size);

void WriteMem(HANDLE hProc, void* dest, BYTE* buffer, size_t size);
