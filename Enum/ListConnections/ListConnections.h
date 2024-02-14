#pragma once

#include <phnt_windows.h>
#include <string>
#include <vector>

enum class ProtocolType
{
    TCP = 0,
    UDP
};

typedef struct
{
    DWORD ownerPid;
    ProtocolType protocol;

    DWORD localAddress;
    std::wstring localAddressStr;
    DWORD localPort;

    DWORD remoteAddress;
    std::wstring remoteAddressStr;
    DWORD remotePort;

    std::wstring state;
} ConnectionInfo;

/*
    Returns a list of TCP connections and UDP ports. (UDP is connectionless)
    #TODO: IPv6
*/
std::vector<ConnectionInfo> GetConnectionsStatus();