#pragma once

#include <windows.h>
#include <string>

void ThrowException(std::string msg);

void ThrowException(char* msg);

bool FileExists(const char* fileName);

void LowerString(std::wstring& str);

size_t ToWideString(const char* mbstr, wchar_t* wstr, size_t max);

/*
    ScanPattern searches for the first ocurrence of "pattern" in "src".
    The mask can contain '?' characters to match any byte.
*/
BYTE* ScanPattern(const BYTE* pattern, const char* mask, const BYTE* src, uintptr_t srcSize);

uintptr_t FindFunctionAddress(const char* moduleName, const char* functionName);