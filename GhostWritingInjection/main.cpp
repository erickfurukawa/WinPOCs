#include "GhostWritingInjection.h"
#include "../Common/PE.h"
#include <iostream>

int main(int argc, char** argv)
{
    DWORD threadId = 0;
    std::string dllPath{};

    if (argc == 3)
    {
        threadId = atoi(argv[1]);
        dllPath = std::string(argv[2]);
    }
    else
    {
        std::cout << "Thread ID:\n";
        std::cin >> threadId;
        std::cout << "Dll path:\n";
        std::cin >> dllPath;
    }

    PE dll = PE(dllPath.c_str());

    if (GhostWritingInjection(threadId, dll))
    {
        std::cout << "Dll has probably been injected successfully\n";
        return 0;
    }
    else
    {
        std::cerr << "Could not inject dll into the target process\n";
        return 1;
    }
}
