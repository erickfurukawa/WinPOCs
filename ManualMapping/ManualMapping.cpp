#include <iostream>
#include <windows.h>
#include <fstream>
#include "../Common/PE.h"
#include "../Common/Process.h"
#include "../Common/Constants.h"

using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

typedef struct ManualMappingData
{
    DWORD status;
    BYTE* baseAddr;
    HMODULE(__stdcall* pLoadLibraryA)(LPCSTR lpLibFilename);
    FARPROC(__stdcall* pGetProcAddress)(HMODULE hmodule, LPCSTR lpProcName);
} ManualMappingData;

void __stdcall Shellcode(ManualMappingData* data);

int main(int argc, char** argv)
{
    char processName[MAX_LENGTH];
    char dllPath[MAX_LENGTH];

    if (argc == 3) {
        strncpy_s(processName, argv[1], MAX_LENGTH);
        strncpy_s(dllPath, argv[2], MAX_LENGTH);
    }
    else {
        std::cout << "Process name:\n";
        std::cin.getline(processName, MAX_LENGTH);
        std::cout << "Dll path:\n";
        std::cin.getline(dllPath, MAX_LENGTH);
    }

    std::cout << "Manual mapping dll " << dllPath << " into process " << processName << "\n\n";

    BYTE* buffer;
    std::ifstream file;
    std::streampos length;

    file.open(dllPath, std::ios::binary);

    file.seekg(0, std::ios::end);
    length = file.tellg();
    buffer = new BYTE[static_cast<int>(length) + 1];

    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buffer), length);
    file.close();

    PEHeaders headers;
    if (GetPEHeaders(reinterpret_cast<char*>(buffer), &headers))
    {
        // open target process
        Process proc = Process(processName);

        if (!proc.Open(PROCESS_CREATE_THREAD | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION))
        {
            std::cerr << "Could not open target process.\n";
            delete[] buffer;
            return 1;
        }

        // allocate memory in the target process
        std::cout << "Allocating memory in the target process...\n";
        std::cout << "SizeOfImage: 0x" << std::hex << headers.pOptionalHeader->SizeOfImage << std::endl;
        BYTE* baseAddr = reinterpret_cast<BYTE*>(proc.AllocMemory(headers.pOptionalHeader->SizeOfImage, reinterpret_cast<void*>(headers.pOptionalHeader->ImageBase)));
        if (!baseAddr)
        {
            baseAddr = reinterpret_cast<BYTE*>(proc.AllocMemory(headers.pOptionalHeader->SizeOfImage));
            if (!baseAddr)
            {
                std::cerr << "Could not allocate memory in the target process.\n";
                delete[] buffer;
                return 1;
            }
        }
        std::cout << "Memory allocated successfully! base address at 0x" << std::hex << reinterpret_cast<void*>(baseAddr) << "\n\n";

        // write headers
        std::cout << "Writing file headers...\n";
        if (!proc.WriteMemory(baseAddr, buffer, headers.pOptionalHeader->SizeOfHeaders))
        {
            std::cerr << "Could not write file headers in the target process.\n";
            delete[] buffer;
            proc.FreeMemory(baseAddr);
            return 1;
        }
        std::cout << "Headers written successfully! Size: 0x" << std::hex << headers.pOptionalHeader->SizeOfHeaders << "\n\n";

        // map sections
        std::cout << "Mapping sections...\n";
        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(headers.pNTHeaders);
        for (int i = 0; i < headers.pFileHeader->NumberOfSections; ++pSectionHeader, i++)
        {
            if (pSectionHeader->SizeOfRawData)
            {
                // section names are up to 8 chars
                std::cout << "Mapping section " << std::string(reinterpret_cast<char*>(pSectionHeader->Name)).substr(0, 8) << std::endl;
                std::cout << "Address: " << std::hex << reinterpret_cast<void*>(baseAddr + pSectionHeader->VirtualAddress)
                    << " size: 0x" << std::hex << pSectionHeader->SizeOfRawData << std::endl;
                if (!proc.WriteMemory(baseAddr + pSectionHeader->VirtualAddress, buffer + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData))
                {
                    std::cerr << "Could not map sections in the target process.\n";
                    delete[] buffer;
                    proc.FreeMemory(baseAddr);
                    return 1;
                }
            }
        }
        std::cout << "Sections mapped successfully!\n\n";
        delete[] buffer;

        // write manual mapping data
        std::cout << "Writing manual mapping data...\n";
        ManualMappingData data;
        data.status = 0;
        data.baseAddr = baseAddr;
        data.pGetProcAddress = GetProcAddress;
        data.pLoadLibraryA = LoadLibraryA;
        BYTE* dataAddr = reinterpret_cast<BYTE*>(proc.AllocMemory(sizeof(ManualMappingData)));
        if (!dataAddr)
        {
            std::cerr << "Could not write manual mapping data in the target process.\n";
            proc.FreeMemory(baseAddr);
            return 1;
        }
        proc.WriteMemory(dataAddr, reinterpret_cast<BYTE*>(&data), sizeof(ManualMappingData));
        std::cout << "Manual mapping data written successfully at 0x" << std::hex << reinterpret_cast<void*>(dataAddr) << "\n\n";

        // inject shellcode
        std::cout << "Injecting loader shellcode...\n";
        BYTE* shellcodeAddr = reinterpret_cast<BYTE*>(proc.AllocMemory(0x1000));
        if (!shellcodeAddr)
        {
            std::cerr << "Could not allocate memory for the shellcode in the target process.\n";
            proc.FreeMemory(baseAddr);
            proc.FreeMemory(dataAddr);
            return 1;
        }
        proc.WriteMemory(shellcodeAddr, reinterpret_cast<BYTE*>(Shellcode), 0x1000);
        std::cout << "Shellcode injected at 0x" << std::hex << reinterpret_cast<void*>(shellcodeAddr) << "\n\n";

        // call shellcode
        std::cout << "Creating remote thread to run the shellcode...\n";
        HANDLE hThread = CreateRemoteThread(proc.handle, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcodeAddr), dataAddr, 0, nullptr);
        if (!hThread)
        {
            std::cerr << "Could not create a thread.\n";
            proc.FreeMemory(baseAddr);
            proc.FreeMemory(dataAddr);
            proc.FreeMemory(shellcodeAddr);
            return 1;
        }
        CloseHandle(hThread);
        std::cout << "Shellcode called successfuly!\n\n";

        // wait for shellcode
        DWORD status = 0;
        while (status != 1)
        {
            std::cout << "Waiting for shellcode to return... status: " << status << "\n";
            Sleep(1000);
            ManualMappingData dataCheck;
            ReadProcessMemory(proc.handle, dataAddr, &dataCheck, sizeof(ManualMappingData), nullptr);
            status = dataCheck.status;
        }
        std::cout << "Shellcode finished! status: " << status << "\n\n";

        // cleanup
        std::cout << "Cleaning up...\n";
        proc.FreeMemory(baseAddr);
        proc.FreeMemory(dataAddr);
        proc.FreeMemory(shellcodeAddr);
        proc.Close();
        std::cout << "Cleanup done!\n";
    }
    else {
        delete[] buffer;
    }

    return 0;
}

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
    if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size)
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