#include "PE.h"
#include "Utils.h"
#include <iostream>
#include <fstream>

PE::PE(char* fileName)
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
    PIMAGE_FILE_HEADER pFileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>(&this->headers.pNTHeaders->FileHeader);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(this->headers.pNTHeaders);

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
DWORD PE::GetExportRVA(char* exportName)
{
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        this->RVAToBufferPointer(this->headers.pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
    DWORD* pfuncNameRVA = reinterpret_cast<DWORD*>(this->RVAToBufferPointer(pExportDirectory->AddressOfNames));
    DWORD* pfuncRVA = reinterpret_cast<DWORD*>(this->RVAToBufferPointer(pExportDirectory->AddressOfFunctions));

    for (int i = 0; i < pExportDirectory->NumberOfNames; i++)
    {
        if (_strcmpi(exportName, reinterpret_cast<char*>(this->RVAToBufferPointer(*pfuncNameRVA))) == 0)
        {
            return *pfuncRVA;
        }
        pfuncNameRVA++;
        pfuncRVA++;
    }
    return 0;
}

// TODO: forwarder RVA
DWORD PE::GetExportRVA(DWORD ordinal) 
{
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        this->RVAToBufferPointer(this->headers.pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
    DWORD* pfuncRVA = reinterpret_cast<DWORD*>(this->RVAToBufferPointer(pExportDirectory->AddressOfFunctions));

    DWORD unbiasedOrdinal = ordinal - pExportDirectory->Base;
    if (unbiasedOrdinal >= 0 && unbiasedOrdinal < pExportDirectory->NumberOfFunctions)
    {
        return pfuncRVA[unbiasedOrdinal];
    }
    return 0;
}

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
    headers->pNTHeaders = pNTHeaders;

    headers->pFileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>(&headers->pNTHeaders->FileHeader);
    headers->pOptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(&headers->pNTHeaders->OptionalHeader);

    return true;
}