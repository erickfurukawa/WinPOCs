#pragma once

#include "MetadataTables.h"
#include <windows.h>
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

        // metadata tables
        metadatatables::BaseTable tables[64];
    } MetadataTablesStream;

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