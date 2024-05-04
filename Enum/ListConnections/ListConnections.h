#pragma once

#include <windows.h>
#include <string>
#include <vector>

enum class ProtocolType
{
    TCP = 0,
    UDP
};

enum class IpVersion
{
    IPv4 = 0,
    IPv6
};

typedef struct
{
    DWORD ownerPid;
    ProtocolType protocol;
    IpVersion ipVersion;

    union
    {
        DWORD localAddressIPv4;
        UCHAR localAddressIPv6[16];
    };
    std::wstring localAddressStr;
    DWORD localPort;

    union
    {
        DWORD remoteAddressIPv4;
        UCHAR remoteAddressIPv6[16];
    };
    std::wstring remoteAddressStr;
    DWORD remotePort;

    std::wstring state;
} ConnectionInfo;

/*
    Returns a list of TCP connections and UDP ports. (UDP is connectionless)
*/
std::vector<ConnectionInfo> GetConnectionsStatus();