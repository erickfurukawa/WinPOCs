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


    // .NET
    unsigned char GetBlobSize(BYTE* address, DWORD* size)
    {
        *size = 0;
        BYTE first = *address;
        BYTE second = *(address + 1);
        BYTE third = *(address + 2);
        BYTE fourth = *(address + 3);

        if ((first & 0b11000000) == 0b11000000)
        {
            first = first & 0b00011111;
            *size += first << 24;
            *size += second << 16;
            *size += third << 8;
            *size += fourth;
            return 4;
        }
        else if ((first & 0b10000000) == 0b10000000)
        {
            first = first & 0b00111111;
            *size += first << 8;
            *size += second;
            return 2;
        }
        else
        {
            *size = first;
            return 1;
        }
    }
}

PE::PE()
{
    //TODO: consider creating a Open(fileName) method 
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

    GetFullPathName(fileName, MAX_PATH, this->filePath, nullptr);

    // get only filename
    std::string fullPath = std::string(this->filePath);
    strncpy_s(this->fileName, fullPath.substr(fullPath.find_last_of("/\\") + 1).c_str(), MAX_LENGTH);

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

    // .NET
    this->isDotNet = this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0;
    if (this->isDotNet)
    {
        this->ParseDotnetMetadata();
    }
}

PE::PE(BYTE* buffer, size_t size)
{
    this->fileSize = size;
    this->buffer = new BYTE[static_cast<int>(this->fileSize)];
    memcpy(this->buffer, buffer, size);

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

    // .NET
    this->isDotNet = this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0;
    if (this->isDotNet)
    {
        this->ParseDotnetMetadata();
    }
}

bool PE::Copy(const PE& from, PE& to)
{
    if (to.buffer != nullptr)
    {
        delete[] to.buffer;
    }
    memcpy((void*)to.filePath, (void*)from.filePath, MAX_PATH);
    memcpy((void*)to.fileName, (void*)from.fileName, MAX_LENGTH);

    // copy buffer
    to.fileSize = from.fileSize;
    to.buffer = new BYTE[to.fileSize];
    memcpy((void*)to.buffer, (void*)from.buffer, to.fileSize);

    to.is32Bits = from.is32Bits;
    to.isDotNet = from.isDotNet;

    // get PE headers
    if (!GetPEHeaders(to.buffer, &to.headers))
    {
        std::cerr << "Could not get valid PE headers";
        return false;
    }

    if (to.is32Bits)
    {
        to.pDataDirectory = to.headers.pOptionalHeader32->DataDirectory;
    }
    else
    {
        to.pDataDirectory = to.headers.pOptionalHeader64->DataDirectory;
    }

    if (to.isDotNet)
    {
        to.ParseDotnetMetadata();
    }

    return true;
}

PE::PE(const PE& pe)
{
    if (!PE::Copy(pe, *this))
    {
        ThrowException(std::string("Could not create copy of PE class"));
    }
}

PE& PE::operator=(const PE& pe)
{
    if (!PE::Copy(pe, *this))
    {
        ThrowException(std::string("Could not assign copy of PE class"));
    }
    return *this;
}

PE::~PE()
{
    if (this->buffer)
    {
        delete[] this->buffer;
        this->buffer = nullptr;
    }
}

BYTE* PE::RVAToBufferPointer(DWORD rva)
{
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

DWORD PE::BufferToRVA(BYTE* buffer)
{
    PIMAGE_FILE_HEADER pFileHeader = this->headers.pFileHeader;
    PIMAGE_SECTION_HEADER pSectionHeader = this->headers.pSectionHeader;

    for (int i = 0; i < pFileHeader->NumberOfSections; i++)
    {
        if (buffer >= this->buffer + pSectionHeader->PointerToRawData 
            && buffer < this->buffer + pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData)
        {
            DWORD offset = static_cast<DWORD>(buffer - this->buffer) - pSectionHeader->PointerToRawData;
            return pSectionHeader->VirtualAddress + offset;
        }
        pSectionHeader++;
    }
    return 0;
}

// TODO: forwarder RVA https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-address-table
DWORD PE::GetExportRVA(const char* exportName)
{
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        this->RVAToBufferPointer(this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
    DWORD* pExportNameRVA = reinterpret_cast<DWORD*>(this->RVAToBufferPointer(pExportDirectory->AddressOfNames));
    DWORD* pExportRVA = reinterpret_cast<DWORD*>(this->RVAToBufferPointer(pExportDirectory->AddressOfFunctions));
    WORD* pOrdinal = reinterpret_cast<WORD*>(this->RVAToBufferPointer(pExportDirectory->AddressOfNameOrdinals));

    for (unsigned int i = 0; i < pExportDirectory->NumberOfNames; i++)
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

BYTE* PE::ScanFile(const BYTE* pattern, const char* mask)
{
    return ScanPattern(pattern, mask, this->buffer, this->fileSize);
}

BYTE* PE::ScanSections(const BYTE* pattern, const char* mask, bool executable)
{
    PIMAGE_FILE_HEADER pFileHeader = this->headers.pFileHeader;
    PIMAGE_SECTION_HEADER pSectionHeader = this->headers.pSectionHeader;

    for (int i = 0; i < pFileHeader->NumberOfSections; i++)
    {
        bool executableSection = pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE;

        if (!executable || executableSection)
        {
            BYTE* match = ScanPattern(pattern, mask, this->buffer + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
            if (match)
            {
                return match;
            }
        }
        pSectionHeader++;
    }
    return nullptr;
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

void PE::ParseUSStream()
{
    BYTE* currAddress = this->dotnetMetadata.usStream.address;
    BYTE* endAddr = currAddress + this->dotnetMetadata.usStream.size;

    // first null byte
    this->dotnetMetadata.usStream.strings.push_back(std::wstring(L""));
    currAddress++;
    while (currAddress < endAddr) {
        DWORD size = 0;
        unsigned char nBytes;
        nBytes = GetBlobSize(currAddress, &size);
        currAddress += nBytes;

        if (size == 0)
        {
            break;
        }
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
                table = new dotnet::metadatatables::Module();
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
            case dotnet::metadatatables::TablesEnum::MethodSpec:
            {
                table = new dotnet::metadatatables::MethodSpec();
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
        table->ReadData(&currAddress, sizes);
        metadata.tables[i] = table;
    }
    this->dotnetMetadata.metadataTablesStream = metadata;
}
