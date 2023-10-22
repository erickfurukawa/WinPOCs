#include "DumpResources.h"
#include <iostream>

int main(int argc, char** argv)
{
    std::string filePath{ 0 };

    if (argc == 2)
    {
        filePath = std::string(argv[1]);
    }
    else
    {
        std::cout << "File path:\n";
        std::cin >> filePath;
    }

    PE file = PE(filePath.c_str());
    if (DumpResources(file))
    {
        std::cout << "Resources dumped successfully!\n";
        return 0;
    }
    std::cerr << "Could not dump resources from file!\n";
    return 1;
}
