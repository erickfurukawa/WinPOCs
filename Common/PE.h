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
    std::string filePath = std::string();
    std::string fileName = std::string();
    BYTE* buffer = nullptr;
    size_t fileSize = 0;
    bool is32Bits = false;
    bool isDotNet = false;

    PEHeaders headers = PEHeaders();
    PIMAGE_DATA_DIRECTORY pDataDirectory = nullptr;
    dotnet::Metadata dotnetMetadata = dotnet::Metadata();

    PE();
    PE(const char* fileName);
    PE(BYTE* buffer, size_t size);
    PE(const PE& pe);
    PE& operator=(const PE& pe);
    ~PE();

    BYTE* RVAToBufferPointer(DWORD rva);
    DWORD BufferToRVA(BYTE* buffer);
    DWORD GetExportRVA(const char* exportName);
    DWORD GetExportRVA(DWORD ordinal);
    DWORD GetImportRVA(const char* moduleName, const char* importName);
    // TODO: ordinal GetImportRVA
    // DWORD GetImportRVA(char* moduleName, DWORD ordinal);

    BYTE* ScanFile(const BYTE* pattern, const char* mask);
    BYTE* ScanSections(const BYTE* pattern, const char* mask, bool executable = false);
    // TODO: multiple scan?
    // TODO: method to get list of sections?
};
