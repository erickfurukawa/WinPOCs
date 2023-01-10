#include "Utils.h"
#include <iostream>
#include <fstream>

void ThrowException(std::string msg)
{
    std::cerr << msg;
    throw std::runtime_error(msg);
}

void ThrowException(char* msg)
{
    ThrowException(std::string(msg));
}

bool FileExists(char* fileName)
{
    std::ifstream file;
    file.open(fileName);
    if (!file.is_open())
    {
        return false;
    }
    file.close();
    return true;
}