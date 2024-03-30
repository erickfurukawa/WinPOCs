#include "Utils.h"
#include <windows.h>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <codecvt>

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

void LowerString(std::wstring& str)
{
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
}

std::string WStringToString(std::wstring wstr)
{
    std::string str;
    size_t size;
    str.resize(wstr.length());
    wcstombs_s(&size, &str[0], str.size() + 1, wstr.c_str(), wstr.size());
    return str;
}

std::wstring StringToWString(std::string str)
{
    std::wstring wstr;
    size_t size;
    wstr.resize(str.length());
    mbstowcs_s(&size, &wstr[0], wstr.size() + 1, str.c_str(), str.size());
    return wstr;
}

BYTE* ScanPattern(const BYTE* pattern, const char* mask, const BYTE* src, uintptr_t srcSize)
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
            return const_cast<BYTE*>(src + i);
        }
    }
    return nullptr;
}

uintptr_t FindFunctionAddress(const char* moduleName, const char* functionName)
{
    HMODULE hMod = GetModuleHandleA(moduleName);
    if (hMod == NULL)
    {
        std::cerr << "Could not find module " << moduleName << std::endl;
        return 0;
    }

    uintptr_t funcAddress = reinterpret_cast<uintptr_t>(GetProcAddress(hMod, functionName));
    if (!funcAddress)
    {
        std::cerr << "Could not find function " << functionName << " in module " << moduleName << std::endl;
        return 0;
    }
    return funcAddress;
}