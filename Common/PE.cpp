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
            metadata.mainStream.streamName = streamName;
            metadata.mainStream.address = metadata.baseAddress + streamOffset;
            metadata.mainStream.size = streamSize;
        }
        else
        {
            ThrowException(std::string("Unrecognized stream name ") + streamName);
        }
    }
    this->dotnetMetadata = metadata;

    this->ParseStringsStream();
    this->ParseUSStream();
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