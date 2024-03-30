#include "PeResource.h"
#include <iostream>
#include <fstream>

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
    std::vector<PeResource> resources = PeResource::GetResources(file);

    int i = 0;
    for (PeResource& resource : resources)
    {
        std::wcout << i << L": " << resource.GetTypeStr() << L" - " << resource.GetIdStr() << L" - " << resource.GetLanguage() << std::endl;

        // dump file
        std::string fileName = "Dump " + std::to_string(i);
        std::ofstream fileDump(fileName.c_str(), std::ios::out | std::ios::binary);
        fileDump.write(reinterpret_cast<char*>(resource.rawData), resource.dataSize);
        fileDump.close();
        i++;
    }
    std::cout << "Resources dumped!\n";
    return 0;
}
