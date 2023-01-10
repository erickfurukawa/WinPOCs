#include "PE.h"
#include "Utils.h"
#include <iostream>
#include <fstream>

PE::PE(char* fileName)
{
    // reads file and allocates buffer
    std::ifstream file;
    file.open(fileName, std::ios::binary);

    if (!file.is_open())
    {
        ThrowException(std::string("Could not open file: ") + fileName);
    }

    GetFullPathName(fileName, MAX_PATH+1, this->filePath, nullptr);

    file.seekg(0, std::ios::end);
    this->fileSize = file.tellg();
    this->buffer = new BYTE[static_cast<int>(this->fileSize) + 1];

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