#include "ManualMapping.h"
#include "../Common/PE.h"
#include "../Common/Process.h"
#include "../Common/Constants.h"
#include <fstream>
#include <iostream>

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
