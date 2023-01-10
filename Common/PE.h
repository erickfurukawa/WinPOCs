#pragma once

#include <windows.h>
#include "Constants.h"

typedef struct PEHeaders
{
    PIMAGE_DOS_HEADER pDOSHeader;
    PIMAGE_NT_HEADERS pNTHeaders;
    PIMAGE_FILE_HEADER pFileHeader;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader;
} PEHeaders;

class PE
{
private:
    PE(const PE&);
    PE& operator=(const PE&);

public:
    PE(char* fileName);
    ~PE();

    char filePath[MAX_PATH+1];

    BYTE* buffer = nullptr;
    size_t fileSize = 0;

    PEHeaders headers;
};

bool GetPEHeaders(BYTE* buffer, PEHeaders* headers);
