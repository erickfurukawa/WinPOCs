#pragma once

#include <windows.h>
#include <string>

void ThrowException(std::string msg);

void ThrowException(char* msg);

bool FileExists(char* fileName);

/*
    ScanPattern searches for the first ocurrence of "pattern" in "src".
    The mask can contain '?' characters to match any byte.
*/
BYTE* ScanPattern(BYTE* pattern, char* mask, BYTE* src, uintptr_t srcSize);