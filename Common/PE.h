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

        // metadata tables
        DWORD numberOfRows[64];
    } MetadataTablesStream;

    enum MetadataTables
    {
        Module = 1,
        TypeRef = 2,
        TypeDef = 4,
        Reserved1 = 8,
        Field = 16,
        Reserved2 = 32,
        Method = 64,
        Reserved3 = 128,
        Param = 256,
        InterfaceImpl = 512,
        MemberRef = 1024,
        Constant = 2048,
        CustomAttribute = 4096,
        FieldMarshal = 8192,
        DeclSecurity = 16384,
        ClassLayout = 32768,
        FieldLayout = 65536,
        StandAloneSig = 131072,
        EventMap = 262144,
        Reserved4 = 524288,
        Event = 1048576,
        PropertyMap = 2097152,
        Reserved5 = 4194304,
        Property = 8388608,
        MethodSemantics = 16777216,
        MethodImpl = 33554432,
        ModuleRef = 67108864,
        TypeSpec = 134217728,
        ImplMap = 268435456,
        FieldRVA = 536870912,
        Reserved6 = 1073741824,
        Reserved7 = 2147483648,
        Assembly = 4294967296,
        AssemblyProcessor = 8589934592,
        AssemblyOS = 17179869184,
        AssemblyRef = 34359738368,
        AssemblyRefProcessor = 68719476736,
        AssemblyRefOS = 137438953472,
        File = 274877906944,
        ExportedType = 549755813888,
        ManifestResource = 1099511627776,
        NestedClass = 2199023255552,
        GenericParam = 4398046511104,
        MethodSpec = 8796093022208,
        GenericParamConstraint = 17592186044416
    };

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
        MetadataTablesStream metadataTablesStream;
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
    void ParseMetadataTablesStream();

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
