#include "DllInjection.h"

int main(int argc, char** argv)
{
    char processName[MAX_LENGTH];
    char dllPath[MAX_PATH];

    if (argc == 3) {
        strncpy_s(processName, argv[1], MAX_LENGTH);
        strncpy_s(dllPath, argv[2], MAX_PATH);
    }
    else {
        std::cout << "Process name:\n";
        std::cin.getline(processName, MAX_LENGTH);
        std::cout << "Dll path:\n";
        std::cin.getline(dllPath, MAX_PATH);
    }

    std::ifstream file;
    file.open(dllPath);
    if (!file)
    {
        std::cerr << "Could not open dll " << dllPath << std::endl;
        return 1;
    }
    file.close();
    GetFullPathName(dllPath, MAX_PATH, dllPath, nullptr);

    std::cout << "Injecting dll " << dllPath << " into process " << processName << std::endl;

    Process proc = Process(processName);
    if (!proc.Open())
    {
        std::cerr << "Could not open target process\n";
        return 1;
    }

    HANDLE hThread = InjectDll(proc, dllPath);
    if (!hThread)
    {
        std::cerr << "Could not inject dll into the target process\n";
        return 1;
    }

    std::cout << "Dll has probably been injected successfully\n";
    CloseHandle(hThread);
    proc.Close();
    return 0;
}
