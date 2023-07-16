#include <iostream>
#include "../Common/Utils.h"
#include "ProxyDllGenerator.h"
#include "../Common/PE.h"

int main(int argc, char** argv)
{
    char dllPath[MAX_PATH + 1];

    if (argc == 2) {
        strncpy_s(dllPath, argv[1], MAX_PATH + 1);
    }
    else {
        std::cout << "Dll path:\n";
        std::cin.getline(dllPath, MAX_PATH + 1);
    }

    if (!FileExists(dllPath))
    {
        std::cerr << "Could not open dll " << dllPath << "\n";
        return 1;
    }

    PE dll = PE(dllPath);
    if (GenerateProxyDll(dll))
    {
        std::cout << "Proxy Dll files generated successfully!\n";
    }
    else
    {
        std::cerr << "Failed to generate proxy dll files\n";
    }
}
