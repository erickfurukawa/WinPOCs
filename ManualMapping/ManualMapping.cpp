#include "ManualMapping.h"
#include "../Common/Constants.h"

/*
    The shellcode is injected in the target process to perform relocations,
    fix the IAT, call the TLS callbacks, and call the DLL entrypoint.
    Because it is compiled in the injector and is injected in an external process,
    the shellcode must only have position independent code. When compiling debug
    builds in Visual Studio, it adds extra function calls for debug purposes, and
    that makes the code not position independent. Because of this behaviour, the
    shellcode will only work if the injector is built in release mode.
*/
void __stdcall Shellcode(ManualMappingData* data) {
    if (!data)
        return;

    data->status = 2;
    PIMAGE_DOS_HEADER pDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(data->baseAddr);
    PIMAGE_NT_HEADERS pNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(data->baseAddr + pDOSHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(&pNTHeaders->OptionalHeader);

    // Relocations
    data->status = 3;
    BYTE* baseDelta = data->baseAddr - pOptHeader->ImageBase;
    if (baseDelta)
    {
        if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
        {
            PIMAGE_BASE_RELOCATION pBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(data->baseAddr + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            while (pBaseRelocation->VirtualAddress)
            {
                BYTE* relocAddress = data->baseAddr + pBaseRelocation->VirtualAddress;
                int entries = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* typeOffset = reinterpret_cast<WORD*>(pBaseRelocation + 1);

                for (int i = 0; i < entries; i++, typeOffset++)
                {
                    if (RELOC_FLAG(*typeOffset))
                    {
                        UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(relocAddress + (*typeOffset & 0xFFF));
                        (*pPatch) += reinterpret_cast<UINT_PTR>(baseDelta);
                    }
                }
                pBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<BYTE*>(pBaseRelocation) + pBaseRelocation->SizeOfBlock);
            }
        }
    }

    // Imports
    data->status = 4;
    if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
    {
        PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(data->baseAddr + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDescriptor->Name)
        {
            char* dllName = reinterpret_cast<char*>(data->baseAddr + pImportDescriptor->Name);
            HMODULE hModule = data->pLoadLibraryA(dllName);
            // pThunkRef: PIMAGE_THUNK_DATA
            UINT_PTR* pThunkRef = reinterpret_cast<UINT_PTR*>(data->baseAddr + pImportDescriptor->OriginalFirstThunk);
            UINT_PTR* pFuncRef = reinterpret_cast<UINT_PTR*>(data->baseAddr + pImportDescriptor->FirstThunk);

            while (*pThunkRef)
            {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                    *pFuncRef = reinterpret_cast<UINT_PTR>(data->pGetProcAddress(hModule, reinterpret_cast<char*>(*pThunkRef & 0xFFFF)));
                }
                else {
                    PIMAGE_IMPORT_BY_NAME pImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(data->baseAddr + (*pThunkRef));
                    *pFuncRef = reinterpret_cast<UINT_PTR>(data->pGetProcAddress(hModule, pImport->Name));
                }
                pThunkRef++;
                pFuncRef++;
            }
            pImportDescriptor++;
        }
    }

    // TLS callbacks
    data->status = 5;
    if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        PIMAGE_TLS_DIRECTORY pTLS = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(data->baseAddr + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        PIMAGE_TLS_CALLBACK* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);

        for (; pCallback && *pCallback; ++pCallback) {
            (*pCallback)(data->baseAddr, DLL_PROCESS_ATTACH, nullptr);
        }
    }

    // call entrypoint
    data->status = 6;
    f_DLL_ENTRY_POINT _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(data->baseAddr + pOptHeader->AddressOfEntryPoint);
    _DllMain(data->baseAddr, DLL_PROCESS_ATTACH, nullptr);
    data->status = 1;
}
