#pragma once

#include <windows.h>
#include "Constants.h"

typedef struct PEHeaders
{
    PIMAGE_DOS_HEADER pDOSHeader;
    union 
    {
        PIMAGE_NT_HEADERS64 pNTHeaders64;
        PIMAGE_NT_HEADERS32 pNTHeaders32;
    };
    PIMAGE_FILE_HEADER pFileHeader;
    union
    {
        PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64;
        PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32;
    };
    PIMAGE_SECTION_HEADER pSectionHeader;
} PEHeaders;

class PE
{
private:
    PE(const PE&);
    PE& operator=(const PE&);

public:
    PE(const char* fileName);
    ~PE();

    BYTE* RVAToBufferPointer(DWORD rva);
    DWORD GetExportRVA(const char* exportName);
    DWORD GetExportRVA(DWORD ordinal);
    DWORD GetImportRVA(const char* moduleName, const char* importName);
    // TODO: ordinal GetImportRVA
    // DWORD GetImportRVA(char* moduleName, DWORD ordinal);

    bool is32Bits;
    char filePath[MAX_PATH+1];
    char fileName[MAX_LENGTH+1];

    BYTE* buffer = nullptr;
    size_t fileSize = 0;

    PEHeaders headers;
    PIMAGE_DATA_DIRECTORY pDataDirectory;
};
