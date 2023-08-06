#include <iostream>
#include <fstream>
#include "PESectionInjection.h"
#include "../Common/Utils.h"

int main(int argc, char** argv)
{
    std::string filePath{ 0 };
    std::string payloadFilePath{ 0 };
    std::string sectionName{ 0 };
    std::string outputFilePath{ 0 };

    if (argc == 5)
    {
        filePath = std::string(argv[1]);
        payloadFilePath = std::string(argv[2]);
        sectionName = std::string(argv[3]);
        outputFilePath = std::string(argv[4]);
    }
    else
    {
        std::cout << "File path:\n";
        std::cin >> filePath;
        std::cout << "Payload file path:\n";
        std::cin >> payloadFilePath;
        std::cout << "New section name:\n";
        std::cin >> sectionName;
        std::cout << "Output file path:\n";
        std::cin >> outputFilePath;
    }

    if (!FileExists(payloadFilePath.c_str()))
    {
        std::cerr << "Could not open file " << payloadFilePath << std::endl;
        return 1;
    }

    // read payload
    std::ifstream payloadFile(payloadFilePath, std::ios::binary);
    payloadFile.seekg(0, payloadFile.end);
    size_t payloadSize = payloadFile.tellg();
    auto payload = std::make_unique<BYTE[]>(payloadSize);
    payloadFile.seekg(0);
    payloadFile.read(reinterpret_cast<char*>(payload.get()), payloadSize);

    PE file = PE(filePath.c_str());
    if (InjectSection(file, sectionName, payload.get(), payloadSize, outputFilePath))
    {
        std::cout << "Section injected successfully!\n";
        return 0;
    }
    else
    {
        std::cerr << "Could not inject section!\n";
        return 1;
    }
}

