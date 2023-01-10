#include <iostream>
#include <fstream>
#include "../Common/Process.h"
#include "../Common/Constants.h"
#include "../Common/Utils.h"
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

    if (!FileExists(pythonDllPath))
    {
        std::cerr << "Could not open dll " << pythonDllPath << "\n";
        return 1;
    }
    if (!FileExists(pythonCodePath))
    {
        std::cerr << "Could not open python code " << pythonCodePath << "\n";
        return 1;
    }
    GetFullPathName(pythonDllPath, MAX_PATH+1, pythonDllPath, nullptr);
    GetFullPathName(pythonCodePath, MAX_PATH+1, pythonCodePath, nullptr);

    // TODO: parse python DLL and get exports addresses instead of using GetProcAddress().
    std::cout << "Loading python dll...\n";
    HMODULE hDll = LoadLibraryA(pythonDllPath);
    if (!hDll)
    {
        std::cerr << "Could not load " << pythonDllPath << " in the injector\n";
        return 1;
    }

    void* Py_InitializeEx = GetProcAddress(hDll, "Py_InitializeEx");
    void* PyRun_SimpleString = GetProcAddress(hDll, "PyRun_SimpleString");
    if (!Py_InitializeEx || !PyRun_SimpleString)
    {
        std::cerr << "Could not find the address of Py_InitializeEx or PyRun_SimpleString in the Python dll\n";
        return 1;
    }
    std::cout << "Python dll loaded successfully!\n\n";

    // Inject dll
    std::cout << "Injecting dll " << pythonDllPath << " into process " << processName << "...\n";
    Process* proc = new Process(processName);
    if (!proc->Open())
    {
        std::cerr << "Could not open target process\n";
        delete proc;
        return 1;
    }
   
    HANDLE hThread = InjectDll(proc, pythonDllPath);
    if (!hThread)
    {
        std::cerr << "Could not inject dll into the target process\n";
        proc->Close();
        delete proc;
        return 1;
    }
    WaitForSingleObject(hThread, 1000);
    CloseHandle(hThread);
    std::cout << "Python dll has probably been injected successfully!\n\n";

    // Call python init
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