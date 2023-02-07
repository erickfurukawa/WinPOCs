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

    BYTE* RVAToBufferPointer(DWORD rva);
    DWORD GetExportRVA(char* exportName);
    DWORD GetExportRVA(DWORD ordinal);
    DWORD GetImportRVA(char* moduleName, char* importName);
    // TODO: ordinal GetImportRVA
    // DWORD GetImportRVA(char* moduleName, DWORD ordinal);

    char filePath[MAX_PATH+1];
    char fileName[MAX_LENGTH+1];

    BYTE* buffer = nullptr;
    size_t fileSize = 0;

    PEHeaders headers;
};
