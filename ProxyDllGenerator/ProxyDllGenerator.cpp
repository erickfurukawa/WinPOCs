#include <iostream>
#include <fstream>
#include <string.h>
#include <format>
#include "../Common/Constants.h"
#include "../Common/Utils.h"
#include "../Common/PE.h"


namespace 
{
    void GenerateCpp(PE* dll)
    {

    }

    bool GenerateDef(PE* dll)
    {
        bool success = false;
        std::string dllName = std::string(dll->fileName).substr(0, strnlen(dll->fileName, MAX_LENGTH+1)-4);
        std::string filename = dllName + ".def";
        std::ofstream defFile;
        defFile.open(filename);

        if (defFile.is_open())
        {
            defFile << std::format("LIBRARY {}", dllName) ;

            defFile.close();
            success = true;
        }
        else 
        {
            std::cerr << "Could not create definition file: " << filename << "\n";
            success = false;
        }

        return success;
    }
}

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

    PE* dll = new PE(dllPath);
    GenerateDef(dll);
    delete dll;
}

