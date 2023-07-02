#pragma once

#include <windows.h>
#include "Constants.h"
#include "Dotnet.h"
#include <vector>
#include <string>

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
    static bool Copy(const PE& from, PE& to);

    // .NET related methods -----
    void ParseDotnetMetadata();
    void ParseStringsStream();
    void ParseUSStream();
    void ParseGUIDStream();
    void ParseMetadataTablesStream();

public:
    char filePath[MAX_PATH + 1] = { 0 };
    char fileName[MAX_LENGTH + 1] = { 0 };
    BYTE* buffer = nullptr;
    size_t fileSize = 0;
    bool is32Bits = false;
    bool isDotNet = false;

    PEHeaders headers = PEHeaders();
    PIMAGE_DATA_DIRECTORY pDataDirectory = nullptr;
    dotnet::Metadata dotnetMetadata = dotnet::Metadata();

    PE();
    PE(const char* fileName);
    PE(const PE& pe);
    PE& operator=(const PE& pe);
    ~PE();

    BYTE* RVAToBufferPointer(DWORD rva);
    DWORD GetExportRVA(const char* exportName);
    DWORD GetExportRVA(DWORD ordinal);
    DWORD GetImportRVA(const char* moduleName, const char* importName);
    // TODO: ordinal GetImportRVA
    // DWORD GetImportRVA(char* moduleName, DWORD ordinal);
};
