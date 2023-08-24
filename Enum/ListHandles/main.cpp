#include <iostream>
#include <stdlib.h>
#include "ListHandles.h"

int main(int argc, char** argv)
{
    DWORD pid = 0;

    if (argc == 2)
    {
        pid = atoi(argv[1]);
    }

    unsigned long allHandlesCount;
    auto handles = GetSystemHandles(&allHandlesCount);
    std::cout << "Total system handle count: " << allHandlesCount << std::endl;
    for (auto& handle : handles)
    {
        if (pid != 0 && handle.processId != pid)
        {
            continue;
        }

        std::wcout << L"PID: " << handle.processId << L" Type: " << handle.handleType << std::endl;
    }
    return 0;
}