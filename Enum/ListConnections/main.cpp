#include <iostream>
#include <stdlib.h>
#include "ListConnections.h"

int main(int argc, char** argv)
{
    DWORD pid = 0;

    if (argc == 2)
    {
        pid = atoi(argv[1]);
    }

    auto connections = GetConnectionsStatus();
    for (auto& connection : connections)
    {
        if (pid != 0 && connection.ownerPid != pid)
        {
            continue;
        }

        std::wstring procotol = L"TCP";
        if (connection.protocol == ProtocolType::UDP)
        {
            procotol = L"UDP";
        }
        std::wcout << L"PID: " << connection.ownerPid << L" Protocol: " << procotol << L" State: " << connection.state << std::endl;
        std::wcout << L"Local: " << connection.localAddressStr << ":" << connection.localPort << std::endl;
        std::wcout << L"Remote: " << connection.remoteAddressStr << ":" << connection.remotePort << std::endl << std::endl;
    }
    return 0;
}