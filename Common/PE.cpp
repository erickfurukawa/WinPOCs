#include "PE.h"

bool GetPEHeaders(char* buffer, PEHeaders* headers) 
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