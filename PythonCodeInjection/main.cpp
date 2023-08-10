#include <iostream>
#include <fstream>
#include "../Common/Process.h"
#include "../Common/Constants.h"
#include "../Common/Utils.h"
#include "../Common/PE.h"
#include "../DllInjection/DllInjection.h"

int main(int argc, char** argv)
{
    char processName[MAX_LENGTH];
    char pythonDllPath[MAX_PATH];
    char pythonCodePath[MAX_PATH];

    if (argc == 4) {
        strncpy_s(processName, argv[1], MAX_LENGTH);
        strncpy_s(pythonDllPath, argv[2], MAX_PATH);
        strncpy_s(pythonCodePath, argv[3], MAX_PATH);
    }
    else 
    {
        std::cout << "Process name:\n";
        std::cin.getline(processName, MAX_LENGTH);
        std::cout << "pythonXX.dll path:\n";
        std::cin.getline(pythonDllPath, MAX_PATH);
        std::cout << "python code path:\n";
        std::cin.getline(pythonCodePath, MAX_PATH);
    }

    if (!FileExists(pythonCodePath))
    {
        std::cerr << "Could not open python code " << pythonCodePath << "\n";
        return 1;
    }
    GetFullPathName(pythonCodePath, MAX_PATH, pythonCodePath, nullptr);

    PE pythonDll = PE(pythonDllPath);
    Process proc = Process(processName);
    if (proc.Open())
    {
        std::cout << "Injecting dll " << pythonDll.filePath << " into process " << processName << "...\n";

        // Inject dll
        HANDLE hThread = InjectDll(proc, pythonDll.filePath.c_str());
        if (!hThread)
        {
            std::cerr << "Could not inject dll into the target process\n";
            proc.Close();
            return 1;
        }
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        std::cout << "Python dll has probably been injected successfully!\n\n";

        // find addresses of Py_InitializeEx and PyRun_SimpleString
        std::cout << "Finding addresses of Py_InitializeEx and PyRun_SimpleString...\n";
        MODULEENTRY32 pythonMod = proc.GetModule(pythonDll.fileName.c_str());
        std::cout << pythonDll.fileName << " base address: 0x" << std::hex << (uintptr_t)pythonMod.modBaseAddr << "\n";

        DWORD Py_InitializeExRVA = pythonDll.GetExportRVA("Py_InitializeEx");
        DWORD PyRun_SimpleStringRVA = pythonDll.GetExportRVA("PyRun_SimpleString");

        if (!Py_InitializeExRVA || !PyRun_SimpleStringRVA)
        {
            std::cerr << "Could not find the address of Py_InitializeEx or PyRun_SimpleString in the Python dll\n";
            proc.Close();
            return 1;
        }
        void* Py_InitializeEx = pythonMod.modBaseAddr + Py_InitializeExRVA;
        void* PyRun_SimpleString = pythonMod.modBaseAddr + PyRun_SimpleStringRVA;
        std::cout << "Py_InitializeEx: 0x" << std::hex << (uintptr_t)Py_InitializeEx << " PyRun_SimpleString: 0x" << std::hex << (uintptr_t)PyRun_SimpleString << "\n\n";

        // Call python Py_InitializeEx
        std::cout << "Calling Py_InitializeEx...\n";
        hThread = CreateRemoteThread(proc.handle, nullptr, 0, (LPTHREAD_START_ROUTINE)Py_InitializeEx, nullptr, 0, nullptr);
        if (!hThread)
        {
            std::cerr << "Could not call Py_InitializeEx in the target process\n";
            proc.Close();
            return 1;
        }
        WaitForSingleObject(hThread, 1000);
        CloseHandle(hThread);
        std::cout << "Py_InitializeEx has probably been called successfully!\n\n";

        // write python code
        std::ifstream file(pythonCodePath, std::ios::binary);
        file.seekg(0, file.end);
        size_t fileSize = file.tellg();
   
        auto codeStr = std::make_unique<BYTE[]>(fileSize + 1);
        file.seekg(0, std::ios::beg);
        file.read(reinterpret_cast<char*>(codeStr.get()), fileSize);
        file.close();

        void* codeAddr = proc.AllocMemory(static_cast<size_t>(fileSize) + 1);
        proc.WriteMemory(codeAddr, codeStr.get(), static_cast<size_t>(fileSize) + 1);
        std::cout << "Code at 0x" << (uintptr_t)codeAddr << std::endl;

        // call PyRun_SimpleString
        std::cout << "Calling PyRun_SimpleString...\n";
        hThread = CreateRemoteThread(proc.handle, nullptr, 0, (LPTHREAD_START_ROUTINE)PyRun_SimpleString, codeAddr, 0, nullptr);
        if (!hThread)
        {
            std::cerr << "Could not call PyRun_SimpleString in the target process\n";
            proc.Close();
            return 1;
        }
        WaitForSingleObject(hThread, 1000);
        CloseHandle(hThread);
        std::cout << "PyRun_SimpleString has probably been called successfully!\n\n";

        proc.Close();
    }
    else
    {
        std::cerr << "Could not open target process\n";
        return 1;
    }
    return 0;
}