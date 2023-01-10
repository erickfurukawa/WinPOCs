#include "ManualMapping.h"
#include "../Common/PE.h"
#include "../Common/Process.h"
#include "../Common/Constants.h"
#include <fstream>
#include <iostream>

int main(int argc, char** argv)
{
    char processName[MAX_LENGTH+1];
    char dllPath[MAX_PATH+1];

    if (argc == 3)
    {
        strncpy_s(processName, argv[1], MAX_LENGTH+1);
        strncpy_s(dllPath, argv[2], MAX_PATH+1);
    }
    else 
    {
        std::cout << "Process name:\n";
        std::cin.getline(processName, MAX_LENGTH+1);
        std::cout << "Dll path:\n";
        std::cin.getline(dllPath, MAX_PATH+1);
    }

    std::cout << "Manual mapping dll " << dllPath << " into process " << processName << "\n\n";

    PE* dll = new PE(dllPath);

    bool success = false;
    PEHeaders headers = dll->headers;

    Process* proc = nullptr;
    BYTE* baseAddr = nullptr;
    BYTE* dataAddr = nullptr;
    BYTE* shellcodeAddr = nullptr;

    proc = new Process(processName);
    if (proc->Open(PROCESS_CREATE_THREAD | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION))
    { 
        // allocate memory in the target process
        std::cout << "Allocating memory in the target process...\n";
        std::cout << "SizeOfImage: 0x" << std::hex << headers.pOptionalHeader->SizeOfImage << std::endl;
        baseAddr = reinterpret_cast<BYTE*>(proc->AllocMemory(headers.pOptionalHeader->SizeOfImage, reinterpret_cast<void*>(headers.pOptionalHeader->ImageBase)));
        if (!baseAddr)
        {
            baseAddr = reinterpret_cast<BYTE*>(proc->AllocMemory(headers.pOptionalHeader->SizeOfImage));
            if (!baseAddr)
            {
                std::cerr << "Could not allocate memory in the target process.\n";
                goto cleanup;
            }
        }
        std::cout << "Memory allocated successfully! base address at 0x" << std::hex << reinterpret_cast<void*>(baseAddr) << "\n\n";

        // write headers
        std::cout << "Writing file headers...\n";
        if (!proc->WriteMemory(baseAddr, dll->buffer, headers.pOptionalHeader->SizeOfHeaders))
        {
            std::cerr << "Could not write file headers in the target process.\n";
            goto cleanup;
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
                if (!proc->WriteMemory(baseAddr + pSectionHeader->VirtualAddress, dll->buffer + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData))
                {
                    std::cerr << "Could not map sections in the target process.\n";
                    goto cleanup;
                }
            }
        }
        std::cout << "Sections mapped successfully!\n\n";

        // write manual mapping data
        std::cout << "Writing manual mapping data...\n";
        ManualMappingData data;
        data.status = 0;
        data.baseAddr = baseAddr;
        data.pGetProcAddress = GetProcAddress;
        data.pLoadLibraryA = LoadLibraryA;
        dataAddr = reinterpret_cast<BYTE*>(proc->AllocMemory(sizeof(ManualMappingData)));
        if (!dataAddr)
        {
            std::cerr << "Could not write manual mapping data in the target process.\n";
            goto cleanup;
        }
        proc->WriteMemory(dataAddr, reinterpret_cast<BYTE*>(&data), sizeof(ManualMappingData));
        std::cout << "Manual mapping data written successfully at 0x" << std::hex << reinterpret_cast<void*>(dataAddr) << "\n\n";

        // inject shellcode
        std::cout << "Injecting loader shellcode...\n";
        shellcodeAddr = reinterpret_cast<BYTE*>(proc->AllocMemory(0x1000));
        if (!shellcodeAddr)
        {
            std::cerr << "Could not allocate memory for the shellcode in the target process.\n";
            goto cleanup;
        }
        proc->WriteMemory(shellcodeAddr, reinterpret_cast<BYTE*>(Shellcode), 0x1000);
        std::cout << "Shellcode injected at 0x" << std::hex << reinterpret_cast<void*>(shellcodeAddr) << "\n\n";

        // call shellcode
        std::cout << "Creating remote thread to run the shellcode...\n";
        HANDLE hThread = CreateRemoteThread(proc->handle, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcodeAddr), dataAddr, 0, nullptr);
        if (!hThread)
        {
            std::cerr << "Could not create a thread.\n";
            goto cleanup;
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
            ReadProcessMemory(proc->handle, dataAddr, &dataCheck, sizeof(ManualMappingData), nullptr);
            status = dataCheck.status;
        }
        std::cout << "Shellcode finished! status: " << status << "\n\n";
        success = true;
    }
    else 
    {
        std::cerr << "Could not open target process.\n";
    }

cleanup:
    std::cout << "Cleaning up...\n";
    if (proc)
    {
        if (proc->handle)
        {
            if (baseAddr)
                proc->FreeMemory(baseAddr);
            if (dataAddr)
                proc->FreeMemory(dataAddr);
            if (shellcodeAddr)
                proc->FreeMemory(shellcodeAddr);
            proc->Close();
        }
        delete proc;
    }
    delete dll;
    std::cout << "Cleanup done!\n";

    if (success)
        return 0;
    return 1;
}