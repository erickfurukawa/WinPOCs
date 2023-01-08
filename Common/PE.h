#pragma once

#include <windows.h>

typedef struct PEHeaders 
{
	PIMAGE_DOS_HEADER pDOSHeader;
	PIMAGE_NT_HEADERS pNTHeaders;
	PIMAGE_FILE_HEADER pFileHeader;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader;
} PEInfo;

bool GetPEHeaders(char* buffer, PEHeaders* headers);
