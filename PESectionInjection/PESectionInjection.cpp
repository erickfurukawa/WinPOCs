#define NOMINMAX
#include <iostream>
#include <fstream>
#include "PESectionInjection.h"

namespace
{
    DWORD GetFileAlignment(PE& pe)
    {
        if (pe.is32Bits)
        {
            return pe.headers.pOptionalHeader32->FileAlignment;
        }
        else
        {
            return pe.headers.pOptionalHeader64->FileAlignment;
        }
    }

    DWORD GetSectionAlignment(PE& pe)
    {
        if (pe.is32Bits)
        {
            return pe.headers.pOptionalHeader64->SectionAlignment;
        }
        else
        {
            return pe.headers.pOptionalHeader64->SectionAlignment;
        }
    }

    DWORD Align(DWORD value, DWORD alignment)
    {
        DWORD aligned = value;
        aligned += (alignment - (aligned % alignment)) % alignment;
        return aligned;
    }
}

bool InjectSection(PE& file, std::string sectionName, BYTE* buffer, size_t bufferSize, std::string outPath)
{
    if (sectionName.length() > 8)
    {
        std::cerr << "Section name have more than 8 characters\n";
        return false;
    }

    unsigned int numberOfSections = file.headers.pFileHeader->NumberOfSections;
    PIMAGE_SECTION_HEADER pSectionHeader = file.headers.pSectionHeader;

    // find maximum virtual address so we can put the new section after
    DWORD maxVirtualAddress = 0;
    DWORD sizeOfRawData = 0;
    for (unsigned int i = 0; i < numberOfSections; i++)
    {
        if (pSectionHeader[i].VirtualAddress > maxVirtualAddress)
        {
            maxVirtualAddress = pSectionHeader[i].VirtualAddress;
            sizeOfRawData = pSectionHeader[i].SizeOfRawData;
        }
    }

    DWORD newSectionOffset = Align(static_cast<DWORD>(file.fileSize), GetFileAlignment(file));
    DWORD newSectionVirtualAddress = Align(maxVirtualAddress + sizeOfRawData, GetSectionAlignment(file));
    DWORD newSectionSizeOfRawData = Align(static_cast<DWORD>(bufferSize), GetFileAlignment(file));

    // allocate new file buffer
    size_t newFileSize = static_cast<size_t>(newSectionSizeOfRawData + newSectionOffset);
    auto newFileBuffer = std::make_unique<BYTE[]>(newFileSize);
    memcpy(newFileBuffer.get(), file.buffer, file.fileSize);

    // create new PE ------------------------------------
    PE newFile = PE(newFileBuffer.get(), newFileSize);

    // set new SizeOfImage (aligned)
    if (newFile.is32Bits)
    {
        newFile.headers.pOptionalHeader32->SizeOfImage = Align(static_cast<DWORD>(bufferSize + newSectionVirtualAddress), GetSectionAlignment(file));
    }
    else
    {
        newFile.headers.pOptionalHeader64->SizeOfImage = Align(static_cast<DWORD>(bufferSize + newSectionVirtualAddress), GetSectionAlignment(file));
    }

    // set new SizeOfCode (aligned)
    if (newFile.is32Bits)
    {
        newFile.headers.pOptionalHeader32->SizeOfCode += newSectionSizeOfRawData;
    }
    else
    {
        newFile.headers.pOptionalHeader64->SizeOfCode += newSectionSizeOfRawData;
    }

    // create new section
    newFile.headers.pFileHeader->NumberOfSections += 1;
    PIMAGE_SECTION_HEADER pNewSectionHeader = &(newFile.headers.pSectionHeader[numberOfSections]);

    pNewSectionHeader->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    pNewSectionHeader->Misc.VirtualSize = static_cast<DWORD>(bufferSize); // only actual data size
    memcpy(pNewSectionHeader->Name, sectionName.c_str(), std::min(sectionName.length() + 1, 8ull));
    pNewSectionHeader->NumberOfLinenumbers = 0;
    pNewSectionHeader->NumberOfRelocations = 0;
    pNewSectionHeader->PointerToLinenumbers = 0;
    pNewSectionHeader->PointerToRawData = static_cast<DWORD>(newSectionOffset); // aligned
    pNewSectionHeader->SizeOfRawData = newSectionSizeOfRawData; // aligned
    pNewSectionHeader->VirtualAddress = static_cast<DWORD>(newSectionVirtualAddress); // aligned

    // copy new section bytes
    memcpy(newFile.buffer + newSectionOffset, buffer, bufferSize);

    // write file to disk
    std::ofstream outFile(outPath, std::ios::binary);
    if (outFile.is_open())
    {
        outFile.write(reinterpret_cast<char*>(newFile.buffer), newFile.fileSize);
        outFile.close();
    }
    else
    {
        std::cerr << "Could not open output file " << outPath << std::endl;
        return false;
    }

    return true;
}