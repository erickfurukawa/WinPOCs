#include "Utils.h"
#include <windows.h>
#include <iostream>
#include <fstream>

void ThrowException(std::string msg)
{
    std::cerr << msg;
    throw std::runtime_error(msg);
}

void ThrowException(char* msg)
{
    ThrowException(std::string(msg));
}

bool FileExists(const char* fileName)
{
    std::ifstream file;
    file.open(fileName);
    if (!file.is_open())
    {
        return false;
    }
    file.close();
    return true;
}

size_t ToWideString(const char* mbstr, wchar_t* wstr, size_t max)
{
    size_t convertedSize;
    mbstowcs_s(&convertedSize, wstr, max, mbstr, max);
    return convertedSize;
}

BYTE* ScanPattern(BYTE* pattern, char* mask, BYTE* src, uintptr_t srcSize)
{
    uintptr_t patternLen = strnlen(mask, srcSize);
    for (uintptr_t i = 0; i < srcSize; i++)
    {
        bool found = true;
        for (uintptr_t j = 0; j < patternLen; j++)
        {
            if (mask[j] != '?') // matches anything
            {
                if (pattern[j] != src[i + j])
                {
                    found = false;
                    break;
                }
            }
        }
        if (found)
        {
            return src + i;
        }
    }
    return nullptr;
}
