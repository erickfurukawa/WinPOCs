#include "PE.h"
#include "Utils.h"
#include <iostream>
#include <fstream>

namespace 
{
    bool GetPEHeaders(BYTE* buffer, PEHeaders* headers)
    {
        PIMAGE_DOS_HEADER pDOSHeader;
        PIMAGE_NT_HEADERS pNTHeaders;
        pDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
        if (pDOSHeader->e_magic != 0x5A4D) // MZ magic
        {
            std::cerr << "Invalid PE file. (Invalid MZ magic)\n";
            return false;
        }

        pNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer + pDOSHeader->e_lfanew);
        if (pNTHeaders->Signature != 0x00004550) // PE\00\00 magic
        {
            std::cerr << "Invalid PE file. (Invalid PE magic)\n";
            return false;
        }

        headers->pDOSHeader = pDOSHeader;
        if (pNTHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) // 32 bits
        {
            headers->pNTHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(pNTHeaders);
            headers->pFileHeader = &headers->pNTHeaders32->FileHeader;
            headers->pOptionalHeader32 = &headers->pNTHeaders32->OptionalHeader;
        }
        else // 64 bits
        {
            headers->pNTHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(pNTHeaders);
            headers->pFileHeader = &headers->pNTHeaders64->FileHeader;
            headers->pOptionalHeader64 = &headers->pNTHeaders64->OptionalHeader;
        }
        headers->pSectionHeader = IMAGE_FIRST_SECTION(headers->pNTHeaders64); // bits doesn`t matter here
        return true;
    }
}

PE::PE(const char* fileName)
{
    // checks if file exists
    std::ifstream file;
    file.open(fileName, std::ios::binary);

    if (!file.is_open())
    {
        ThrowException(std::string("Could not open file: ") + fileName);
    }

    GetFullPathName(fileName, MAX_PATH+1, this->filePath, nullptr);

    // get only filename
    std::string fullPath = std::string(this->filePath);
    strncpy_s(this->fileName, fullPath.substr(fullPath.find_last_of("/\\") + 1).c_str(), MAX_LENGTH + 1);

    // get file size and allocate buffer
    file.seekg(0, std::ios::end);
    this->fileSize = file.tellg();
    this->buffer = new BYTE[static_cast<int>(this->fileSize)];

    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(this->buffer), this->fileSize);
    file.close();

    // get PE headers
    if (!GetPEHeaders(this->buffer, &this->headers)) 
    {
        ThrowException("Could not get valid PE headers");
    }

    this->is32Bits = this->headers.pFileHeader->Machine == IMAGE_FILE_MACHINE_I386;
    if (this->is32Bits)
    {
        this->pDataDirectory = this->headers.pOptionalHeader32->DataDirectory;
    } 
    else
    {
        this->pDataDirectory = this->headers.pOptionalHeader64->DataDirectory;
    }

    // dotnet
    this->isDotNet = this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0;
    if (this->isDotNet)
    {
        this->ParseDotnetMetadata();
    }
}

PE::~PE()
{
    if (this->buffer)
    {
        delete[] this->buffer;
        this->buffer = nullptr;
    }
}

BYTE* PE::RVAToBufferPointer(DWORD rva) {
    PIMAGE_FILE_HEADER pFileHeader = this->headers.pFileHeader;
    PIMAGE_SECTION_HEADER pSectionHeader = this->headers.pSectionHeader;

    for (int i = 0; i < pFileHeader->NumberOfSections; i++) 
    {
        if (rva >= pSectionHeader->VirtualAddress && rva < pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
        {
            DWORD offset = rva - pSectionHeader->VirtualAddress;
            return reinterpret_cast<BYTE*>(this->buffer + pSectionHeader->PointerToRawData + offset);
        }
        pSectionHeader++;
    }
    return nullptr;
}

// TODO: forwarder RVA https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-address-table
DWORD PE::GetExportRVA(const char* exportName)
{
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        this->RVAToBufferPointer(this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
    DWORD* pExportNameRVA = reinterpret_cast<DWORD*>(this->RVAToBufferPointer(pExportDirectory->AddressOfNames));
    DWORD* pExportRVA = reinterpret_cast<DWORD*>(this->RVAToBufferPointer(pExportDirectory->AddressOfFunctions));
    WORD* pOrdinal = reinterpret_cast<WORD*>(this->RVAToBufferPointer(pExportDirectory->AddressOfNameOrdinals));

    for (int i = 0; i < pExportDirectory->NumberOfNames; i++)
    {
        if (_strcmpi(exportName, reinterpret_cast<char*>(this->RVAToBufferPointer(*pExportNameRVA))) == 0)
        {
            return pExportRVA[*pOrdinal];
        }
        pExportNameRVA++;
        pOrdinal++;
    }
    return 0;
}

// TODO: forwarder RVA
DWORD PE::GetExportRVA(DWORD ordinal) 
{
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        this->RVAToBufferPointer(this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
    DWORD* pExportRVA = reinterpret_cast<DWORD*>(this->RVAToBufferPointer(pExportDirectory->AddressOfFunctions));

    DWORD unbiasedOrdinal = ordinal - pExportDirectory->Base;
    if (unbiasedOrdinal >= 0 && unbiasedOrdinal < pExportDirectory->NumberOfFunctions)
    {
        return pExportRVA[unbiasedOrdinal];
    }
    return 0;
}

DWORD PE::GetImportRVA(const char* moduleName, const char* importName)
{
    int ptrSize = this->is32Bits ? 4 : 8;
    unsigned long long snapByOrdinalFlag = this->is32Bits ? IMAGE_ORDINAL_FLAG32 : IMAGE_ORDINAL_FLAG64;

    if (this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
    {
        PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
            this->RVAToBufferPointer(this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));

        while (pImportDescriptor->Name)
        {
            char* dllName = reinterpret_cast<char*>(this->RVAToBufferPointer(pImportDescriptor->Name));
            if (_strcmpi(moduleName, dllName) == 0)
            {
                UINT_PTR* pThunkRef = reinterpret_cast<UINT_PTR*>(this->RVAToBufferPointer(pImportDescriptor->OriginalFirstThunk));
                DWORD IATEntryRVA = pImportDescriptor->FirstThunk;
                while (*pThunkRef)
                {
                    if (!(snapByOrdinalFlag & *pThunkRef))
                    {
                        DWORD hintRVA = (*pThunkRef) & ((1llu << 32) - 1); // hint is only 31 lowest bits
                        PIMAGE_IMPORT_BY_NAME pImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(this->RVAToBufferPointer(hintRVA));
                        if (_strcmpi(importName, pImport->Name) == 0)
                        {
                            return IATEntryRVA;
                        }
                    }
                    pThunkRef = reinterpret_cast<UINT_PTR*>(reinterpret_cast<uintptr_t>(pThunkRef) + ptrSize);
                    IATEntryRVA += ptrSize;
                }
            }
            pImportDescriptor++;
        }
    }
    std::cerr << "Could not find IAT entry for " << moduleName << "." << importName << "\n";
    return 0;
}

void PE::ParseDotnetMetadata()
{
    dotnet::Metadata metadata;
    metadata.pCorHeader = reinterpret_cast<PIMAGE_COR20_HEADER>(this->RVAToBufferPointer(this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress));

    BYTE* currAddress = this->RVAToBufferPointer(metadata.pCorHeader->MetaData.VirtualAddress);
    metadata.baseAddress = currAddress;

    metadata.signature = *reinterpret_cast<DWORD*>(currAddress);
    currAddress += sizeof(DWORD);

    metadata.majorVersion = *reinterpret_cast<WORD*>(currAddress);
    currAddress += sizeof(WORD);

    metadata.minorVersion = *reinterpret_cast<WORD*>(currAddress);
    currAddress += sizeof(WORD);

    metadata.reserved = *reinterpret_cast<DWORD*>(currAddress);
    currAddress += sizeof(DWORD);

    metadata.versionStrLen = *reinterpret_cast<DWORD*>(currAddress);
    currAddress += sizeof(DWORD);

    metadata.versionStr = std::string(reinterpret_cast<char*>(currAddress));
    currAddress += metadata.versionStrLen;

    metadata.flags = *reinterpret_cast<WORD*>(currAddress);
    currAddress += sizeof(WORD);

    metadata.streams = *reinterpret_cast<WORD*>(currAddress);
    currAddress += sizeof(WORD);

    metadata.streamHeaders = currAddress;

    // streams ----------

    BYTE* currAddr = metadata.streamHeaders;
    for (int i = 0; i < metadata.streams; i++)
    {
        DWORD streamOffset = *reinterpret_cast<DWORD*>(currAddr);
        currAddr += sizeof(DWORD);
        DWORD streamSize = *reinterpret_cast<DWORD*>(currAddr);
        currAddr += sizeof(DWORD);

        // stream name string is 4 byte aligned
        currAddr +=  (4 - (uintptr_t)currAddr % 4) % 4;

        std::string streamName = std::string(reinterpret_cast<char*>(currAddr));
        currAddr += streamName.size() + 1;

        // next entry (streamOffset) is 4 byte aligned
        currAddr += (4 - (uintptr_t)currAddr % 4) % 4;

        if (streamName == "#Strings")
        {
            metadata.stringsStream.streamName = streamName;
            metadata.stringsStream.address = metadata.baseAddress + streamOffset;
            metadata.stringsStream.size = streamSize;
        }
        else if (streamName == "#US")
        {
            metadata.usStream.streamName = streamName;
            metadata.usStream.address = metadata.baseAddress + streamOffset;
            metadata.usStream.size = streamSize;
        }
        else if (streamName == "#Blob")
        {
            metadata.blobStream.streamName = streamName;
            metadata.blobStream.address = metadata.baseAddress + streamOffset;
            metadata.blobStream.size = streamSize;
        }
        else if (streamName == "#GUID")
        {
            metadata.guidStream.streamName = streamName;
            metadata.guidStream.address = metadata.baseAddress + streamOffset;
            metadata.guidStream.size = streamSize;
        }
        else if (streamName == "#~")
        {
            metadata.metadataTablesStream.streamName = streamName;
            metadata.metadataTablesStream.address = metadata.baseAddress + streamOffset;
            metadata.metadataTablesStream.size = streamSize;
        }
        else
        {
            ThrowException(std::string("Unrecognized stream name ") + streamName);
        }
    }
    this->dotnetMetadata = metadata;

    this->ParseStringsStream();
    this->ParseUSStream();
    this->ParseGUIDStream();
    this->ParseMetadataTablesStream();
}

void PE::ParseStringsStream()
{
    BYTE* currAddress = this->dotnetMetadata.stringsStream.address;
    BYTE* endAddr = currAddress + this->dotnetMetadata.stringsStream.size;

    // first null byte
    this->dotnetMetadata.stringsStream.strings.push_back(std::string(""));
    currAddress++;
    while (currAddress < endAddr) {
        std::string theStr = std::string(reinterpret_cast<char*>(currAddress));
        if (theStr.size() == 0) 
        {
            break;
        }
        this->dotnetMetadata.stringsStream.strings.push_back(theStr);
        currAddress += theStr.size() + 1;
    }
}

// TODO: fix. it's broken
void PE::ParseUSStream()
{
    BYTE* currAddress = this->dotnetMetadata.usStream.address;
    BYTE* endAddr = currAddress + this->dotnetMetadata.usStream.size;

    // first null byte
    this->dotnetMetadata.usStream.strings.push_back(std::wstring(L""));
    currAddress++;
    while (currAddress < endAddr) {
        UINT8 size = *reinterpret_cast<UINT8*>(currAddress);
        if (size == 0)
        {
            break;
        }
        currAddress++;
        std::wstring theStr = std::wstring(reinterpret_cast<wchar_t*>(currAddress), size / 2);
        this->dotnetMetadata.usStream.strings.push_back(theStr);
        currAddress += size;
    }
}

void PE::ParseGUIDStream()
{
    BYTE* currAddress = this->dotnetMetadata.guidStream.address;
    BYTE* endAddr = currAddress + this->dotnetMetadata.guidStream.size;

    while (currAddress < endAddr) {
        BYTE* guid = currAddress;
        char str[37] = {};
        unsigned long time_low = *reinterpret_cast<unsigned long*>(guid);
        unsigned short time_mid = *reinterpret_cast<unsigned short*>(guid + 4);
        unsigned short time_hi_and_version = *reinterpret_cast<unsigned short*>(guid + 6);
        // TODO: clock_seq and node https://en.wikipedia.org/wiki/Universally_unique_identifier#Format

        sprintf_s(str,
            "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            time_low, time_mid, time_hi_and_version,
            guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
        );
        std::string theStr = std::string(str);
        this->dotnetMetadata.guidStream.guids.push_back(theStr);
        currAddress += 16;
    }
}

void PE::ParseMetadataTablesStream()
{
    BYTE* currAddress = this->dotnetMetadata.metadataTablesStream.address;
    BYTE* endAddr = currAddress + this->dotnetMetadata.metadataTablesStream.size;

    dotnet::MetadataTablesStream metadata = this->dotnetMetadata.metadataTablesStream;

    metadata.reserved1 = *reinterpret_cast<DWORD*>(currAddress);
    currAddress += sizeof(DWORD);

    metadata.majorVersion = *reinterpret_cast<BYTE*>(currAddress);
    currAddress += sizeof(BYTE);

    metadata.minorVersion = *reinterpret_cast<BYTE*>(currAddress);
    currAddress += sizeof(BYTE);

    metadata.heapOffsetSizes = *reinterpret_cast<BYTE*>(currAddress);
    currAddress += sizeof(BYTE);

    metadata.reserved2 = *reinterpret_cast<BYTE*>(currAddress);
    currAddress += sizeof(BYTE);

    metadata.valid = *reinterpret_cast<unsigned long long*>(currAddress);
    currAddress += sizeof(unsigned long long);

    metadata.sorted = *reinterpret_cast<unsigned long long*>(currAddress);
    currAddress += sizeof(unsigned long long);

    // get number of rows of the metadata tables
    DWORD tableRows[64];
    for (int i = 0; i < 64; i++)
    {
        if (1ull << i & metadata.valid)
        {
            tableRows[i] = *reinterpret_cast<DWORD*>(currAddress);
            currAddress += sizeof(DWORD);
        }
        else
        {
            tableRows[i] = 0;
        }
    }
    dotnet::metadatatables::IndexSizes sizes = dotnet::metadatatables::GetIndexSizes(tableRows, metadata.heapOffsetSizes);

    // metadata tables
    for (int i = 0; i < 64; i++)
    {
        DWORD numberOfRows = tableRows[i];
        dotnet::metadatatables::BaseTable* table;
        switch (i)
        {
        case dotnet::metadatatables::TablesEnum::Module:
        {
            dotnet::metadatatables::Module* moduleTable = new dotnet::metadatatables::Module();
            moduleTable->numberOfRows = numberOfRows;
            moduleTable->ReadData(&currAddress, sizes);

            table = moduleTable;
            break;
        }
        case dotnet::metadatatables::TablesEnum::TypeRef:
        {
            table = new dotnet::metadatatables::TypeRef();
            break;
        }
        case dotnet::metadatatables::TablesEnum::TypeDef:
        {
            table = new dotnet::metadatatables::TypeDef();
            break;
        }
        case dotnet::metadatatables::TablesEnum::Field:
        {
            table = new dotnet::metadatatables::Field();
            break;
        }
        case dotnet::metadatatables::TablesEnum::MethodDef:
        {
            table = new dotnet::metadatatables::MethodDef();
            break;
        }
        case dotnet::metadatatables::TablesEnum::Param:
        {
            table = new dotnet::metadatatables::Param();
            break;
        }
        case dotnet::metadatatables::TablesEnum::InterfaceImpl:
        {
            table = new dotnet::metadatatables::InterfaceImpl();
            break;
        }
        case dotnet::metadatatables::TablesEnum::MemberRef:
        {
            table = new dotnet::metadatatables::MemberRef();
            break;
        }
        case dotnet::metadatatables::TablesEnum::Constant:
        {
            table = new dotnet::metadatatables::Constant();
            break;
        }
        case dotnet::metadatatables::TablesEnum::CustomAttribute:
        {
            table = new dotnet::metadatatables::CustomAttribute();
            break;
        }
        case dotnet::metadatatables::TablesEnum::FieldMarshal:
        {
            table = new dotnet::metadatatables::FieldMarshal();
            break;
        }
        case dotnet::metadatatables::TablesEnum::DeclSecurity:
        {
            table = new dotnet::metadatatables::DeclSecurity();
            break;
        }
        case dotnet::metadatatables::TablesEnum::ClassLayout:
        {
            table = new dotnet::metadatatables::ClassLayout();
            break;
        }
        case dotnet::metadatatables::TablesEnum::FieldLayout:
        {
            table = new dotnet::metadatatables::FieldLayout();
            break;
        }
        case dotnet::metadatatables::TablesEnum::StandAloneSig:
        {
            table = new dotnet::metadatatables::StandAloneSig();
            break;
        }
        case dotnet::metadatatables::TablesEnum::EventMap:
        {
            table = new dotnet::metadatatables::EventMap();
            break;
        }
        case dotnet::metadatatables::TablesEnum::Event:
        {
            table = new dotnet::metadatatables::Event();
            break;
        }
        case dotnet::metadatatables::TablesEnum::PropertyMap:
        {
            table = new dotnet::metadatatables::PropertyMap();
            break;
        }
        case dotnet::metadatatables::TablesEnum::Property:
        {
            table = new dotnet::metadatatables::Property();
            break;
        }
        case dotnet::metadatatables::TablesEnum::MethodSemantics:
        {
            table = new dotnet::metadatatables::MethodSemantics();
            break;
        }
        case dotnet::metadatatables::TablesEnum::MethodImpl:
        {
            table = new dotnet::metadatatables::MethodImpl();
            break;
        }
        case dotnet::metadatatables::TablesEnum::ModuleRef:
        {
            table = new dotnet::metadatatables::ModuleRef();
            break;
        }
        case dotnet::metadatatables::TablesEnum::TypeSpec:
        {
            table = new dotnet::metadatatables::TypeSpec();
            break;
        }
        case dotnet::metadatatables::TablesEnum::ImplMap:
        {
            table = new dotnet::metadatatables::ImplMap();
            break;
        }
        case dotnet::metadatatables::TablesEnum::FieldRVA:
        {
            table = new dotnet::metadatatables::FieldRVA();
            break;
        }
        case dotnet::metadatatables::TablesEnum::Assembly:
        {
            table = new dotnet::metadatatables::Assembly();
            break;
        }
        case dotnet::metadatatables::TablesEnum::AssemblyProcessor:
        {
            table = new dotnet::metadatatables::AssemblyProcessor();
            break;
        }
        case dotnet::metadatatables::TablesEnum::AssemblyOS:
        {
            table = new dotnet::metadatatables::AssemblyOS();
            break;
        }
        case dotnet::metadatatables::TablesEnum::AssemblyRef:
        {
            table = new dotnet::metadatatables::AssemblyRef();
            break;
        }
        case dotnet::metadatatables::TablesEnum::AssemblyRefProcessor:
        {
            table = new dotnet::metadatatables::AssemblyRefProcessor();
            break;
        }
        case dotnet::metadatatables::TablesEnum::AssemblyRefOS:
        {
            table = new dotnet::metadatatables::AssemblyRefOS();
            break;
        }
        case dotnet::metadatatables::TablesEnum::File:
        {
            table = new dotnet::metadatatables::File();
            break;
        }
        case dotnet::metadatatables::TablesEnum::ExportedType:
        {
            table = new dotnet::metadatatables::ExportedType();
            break;
        }
        case dotnet::metadatatables::TablesEnum::ManifestResource:
        {
            table = new dotnet::metadatatables::ManifestResource();
            break;
        }
        case dotnet::metadatatables::TablesEnum::NestedClass:
        {
            table = new dotnet::metadatatables::NestedClass();
            break;
        }
        case dotnet::metadatatables::TablesEnum::GenericParam:
        {
            table = new dotnet::metadatatables::GenericParam();
            break;
        }
        case dotnet::metadatatables::TablesEnum::GenericParamConstraint:
        {
            table = new dotnet::metadatatables::GenericParamConstraint();
            break;
        }
        default:
            table = new dotnet::metadatatables::BaseTable();
        }
        table->numberOfRows = tableRows[i];
        metadata.tables[i] = table;
    }
    this->dotnetMetadata.metadataTablesStream = metadata;
}
