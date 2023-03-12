#pragma once

#include <windows.h>
#include "Constants.h"
#include <vector>
#include <string>

namespace dotnet
{
    typedef struct StringsStream
    {
        std::string streamName;
        BYTE* address;
        DWORD size;
        std::vector<std::string> strings;
    } StringsStream;

    typedef struct USStream
    {
        std::string streamName;
        BYTE* address;
        DWORD size;
        std::vector<std::wstring> strings;
    } USStream;

    typedef struct BlobStream
    {
        std::string streamName;
        BYTE* address;
        DWORD size;
    } BlobStream;

    typedef struct GUIDStream
    {
        std::string streamName;
        BYTE* address;
        DWORD size;
        std::vector<std::string> guids;
    } GUIDStream;

    typedef struct MetadataTablesStream
    {
        std::string streamName;
        BYTE* address;
        DWORD size;

        DWORD reserved1; // always 0
        BYTE majorVersion;
        BYTE minorVersion;
        BYTE heapOffsetSizes;
        BYTE reserved2; // always 1
        unsigned long long valid;
        unsigned long long sorted;

        // determined by heapOffsetSizes;
        unsigned int stringIndexSize;
        unsigned int guidIndexSize;
        unsigned int blobIndexSize;
    } MainStream;

    typedef struct Metadata
    {
        PIMAGE_COR20_HEADER pCorHeader;
        BYTE* baseAddress;
        DWORD signature; // 0x424A5342
        WORD majorVersion; // ignored, always 1
        WORD minorVersion; // ignored, always 1
        DWORD reserved; // always 0
        DWORD versionStrLen;
        std::string versionStr;
        WORD flags; // always 0
        WORD streams;
        BYTE* streamHeaders;

        // streams
        StringsStream stringsStream;
        USStream usStream;
        BlobStream blobStream;
        GUIDStream guidStream;
        MainStream metadataTablesStream;
    } Metadata;
}

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

    // dotnet related methods -----
    void ParseDotnetMetadata();
    void ParseStringsStream();
    void ParseUSStream();
    void ParseGUIDStream();

public:
    PE(const char* fileName);
    ~PE();

    BYTE* RVAToBufferPointer(DWORD rva);
    DWORD GetExportRVA(const char* exportName);
    DWORD GetExportRVA(DWORD ordinal);
    DWORD GetImportRVA(const char* moduleName, const char* importName);
    // TODO: ordinal GetImportRVA
    // DWORD GetImportRVA(char* moduleName, DWORD ordinal);

    dotnet::Metadata dotnetMetadata;
    bool is32Bits;
    bool isDotNet;
    char filePath[MAX_PATH+1];
    char fileName[MAX_LENGTH+1];

    BYTE* buffer = nullptr;
    size_t fileSize = 0;

    PEHeaders headers;
    PIMAGE_DATA_DIRECTORY pDataDirectory;
};
