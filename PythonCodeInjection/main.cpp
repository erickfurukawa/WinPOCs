#include <iostream>
#include <fstream>
#include "../Common/Process.h"
#include "../Common/Constants.h"
#include "../Common/Utils.h"
#include "../Common/PE.h"
#include "../DllInjection/DllInjection.h"

int main(int argc, char** argv)
{
    char processName[MAX_LENGTH+1];
    char pythonDllPath[MAX_PATH+1];
    char pythonCodePath[MAX_PATH+1];

    if (argc == 4) {
        strncpy_s(processName, argv[1], MAX_LENGTH+1);
        strncpy_s(pythonDllPath, argv[2], MAX_PATH+1);
        strncpy_s(pythonCodePath, argv[3], MAX_PATH+1);
    }
    else {
        std::cout << "Process name:\n";
        std::cin.getline(processName, MAX_LENGTH+1);
        std::cout << "pythonXX.dll path:\n";
        std::cin.getline(pythonDllPath, MAX_PATH+1);
        std::cout << "python code path:\n";
        std::cin.getline(pythonCodePath, MAX_PATH+1);
    }

    if (!FileExists(pythonCodePath))
    {
        std::cerr << "Could not open python code " << pythonCodePath << "\n";
        return 1;
    }
    GetFullPathName(pythonCodePath, MAX_PATH+1, pythonCodePath, nullptr);

    //TODO: proper cleanup
    // Inject dll
    PE* pythonDll = new PE(pythonDllPath);
    std::cout << "Injecting dll " << pythonDll->filePath << " into process " << processName << "...\n";
    Process* proc = new Process(processName);
    if (!proc->Open())
    {
        std::cerr << "Could not open target process\n";
        delete proc;
        delete pythonDll;
        return 1;
    }
   
    HANDLE hThread = InjectDll(proc, pythonDll->filePath);
    if (!hThread)
    {
        std::cerr << "Could not inject dll into the target process\n";
        proc->Close();
        delete proc;
        delete pythonDll;
        return 1;
    }
    WaitForSingleObject(hThread, 1000);
    CloseHandle(hThread);
    std::cout << "Python dll has probably been injected successfully!\n\n";

    // find addresses of Py_InitializeEx and PyRun_SimpleString
    std::cout << "Finding addresses of Py_InitializeEx and PyRun_SimpleString...\n";
    MODULEENTRY32 pythonMod = proc->GetModule(pythonDll->fileName);
    std::cout <<  pythonDll->fileName << " base address: 0x" << std::hex << (uintptr_t)pythonMod.modBaseAddr << "\n";

    DWORD Py_InitializeExRVA = pythonDll->GetExportRVA((char*)"Py_InitializeEx");
    DWORD PyRun_SimpleStringRVA = pythonDll->GetExportRVA((char*)"PyRun_SimpleString");
    delete pythonDll;

    if (!Py_InitializeExRVA || !PyRun_SimpleStringRVA)
    {
        std::cerr << "Could not find the address of Py_InitializeEx or PyRun_SimpleString in the Python dll\n";
        proc->Close();
        delete proc;
        return 1;
    }

    void* Py_InitializeEx = pythonMod.modBaseAddr + Py_InitializeExRVA;
    void* PyRun_SimpleString = pythonMod.modBaseAddr + PyRun_SimpleStringRVA;
    std::cout << "Py_InitializeEx: 0x" << std::hex << (uintptr_t)Py_InitializeEx << " PyRun_SimpleString: 0x" << std::hex << (uintptr_t)PyRun_SimpleString << "\n\n";

    // Call python Py_InitializeEx
    std::cout << "Calling Py_InitializeEx...\n";
    hThread = CreateRemoteThread(proc->handle, nullptr, 0, (LPTHREAD_START_ROUTINE)Py_InitializeEx, nullptr, 0, nullptr);
    if (!hThread)
    {
        std::cerr << "Could not call Py_InitializeEx in the target process\n";
        proc->Close();
        delete proc;
        return 1;
    }
    WaitForSingleObject(hThread, 1000);
    CloseHandle(hThread);
    std::cout << "Py_InitializeEx has probably been called successfully!\n\n";

    // write python code
    std::ifstream file;

    file.open(pythonCodePath);

    file.seekg(0, std::ios::end);
    std::streampos length = file.tellg();

    BYTE* codeStr = new BYTE[static_cast<int>(length) + 1];
    codeStr[static_cast<int>(length)] = 0;

    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(codeStr), length);
    file.close();

    void* codeAddr = proc->AllocMemory(static_cast<size_t>(length) + 1);
    proc->WriteMemory(codeAddr, codeStr, static_cast<size_t>(length) + 1);
    delete[] codeStr;

    // call PyRun_SimpleString
    std::cout << "Calling PyRun_SimpleString...\n";
    hThread = CreateRemoteThread(proc->handle, nullptr, 0, (LPTHREAD_START_ROUTINE)PyRun_SimpleString, codeAddr, 0, nullptr);
    if (!hThread)
    {
        std::cerr << "Could not call PyRun_SimpleString in the target process\n";
        proc->Close();
        delete proc;
        return 1;
    }
    WaitForSingleObject(hThread, 1000);
    CloseHandle(hThread);
    std::cout << "PyRun_SimpleString has probably been called successfully!\n\n";

    proc->Close();
   
    delete proc;
    return 0;
}