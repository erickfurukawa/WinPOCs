#include "ListConnections.h"
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <memory>
#include <iostream>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace
{
	typedef struct _MIB_TCP6ROW_OWNER_PID {
		UCHAR ucLocalAddr[16];
		DWORD dwLocalScopeId;
		DWORD dwLocalPort;
		UCHAR ucRemoteAddr[16];
		DWORD dwRemoteScopeId;
		DWORD dwRemotePort;
		DWORD dwState;
		DWORD dwOwningPid;
	} MIB_TCP6ROW_OWNER_PID, *PMIB_TCP6ROW_OWNER_PID;

	typedef struct _MIB_TCP6TABLE_OWNER_PID {
		DWORD                 dwNumEntries;
		MIB_TCP6ROW_OWNER_PID table[ANY_SIZE];
	} MIB_TCP6TABLE_OWNER_PID, *PMIB_TCP6TABLE_OWNER_PID;

	typedef struct _MIB_UDP6ROW_OWNER_PID {
		UCHAR ucLocalAddr[16];
		DWORD dwLocalScopeId;
		DWORD dwLocalPort;
		DWORD dwOwningPid;
	} MIB_UDP6ROW_OWNER_PID, * PMIB_UDP6ROW_OWNER_PID;

	typedef struct _MIB_UDP6TABLE_OWNER_PID {
		DWORD                 dwNumEntries;
		MIB_UDP6ROW_OWNER_PID table[ANY_SIZE];
	} MIB_UDP6TABLE_OWNER_PID, * PMIB_UDP6TABLE_OWNER_PID;

	std::wstring DwordToIpString(DWORD address)
	{
		BYTE* addrByte = reinterpret_cast<BYTE*>(&address);
		unsigned int first = *addrByte;
		unsigned int second = *(addrByte + 1);
		unsigned int third = *(addrByte + 2);
		unsigned int fourth = *(addrByte + 3);
		std::wstring ip = std::to_wstring(first) + L"." + std::to_wstring(second) + L"." + std::to_wstring(third) + L"." + std::to_wstring(fourth);
		return ip;
	}

	std::wstring IPv6ToIpString(UCHAR* address)
	{
		wchar_t ipBuffer[40] = {0};
		swprintf_s(ipBuffer, L"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			address[0], address[1], address[2], address[3], address[4], address[5], address[6], address[7], 
			address[8], address[9], address[10], address[11], address[12], address[13], address[14], address[15]);

		return std::wstring(ipBuffer);
	}

	bool GetTcpConnectionTable(IpVersion ipVersion, TCP_TABLE_CLASS tableClass, std::unique_ptr<BYTE[]>& buffer)
	{
		unsigned long bufferSize = 0;
		ULONG ipVer = ipVersion == IpVersion::IPv4 ? AF_INET : AF_INET6;

#pragma warning(suppress : 28020) // this warning makes no sense since we are just trying to get the necessary size
		DWORD dwReturn = GetExtendedTcpTable(nullptr, &bufferSize, TRUE, ipVer, tableClass, 0);
		if (dwReturn != ERROR_INSUFFICIENT_BUFFER)
		{
			std::cerr << "GetExtendedTcpTable error 0x" << std::hex << dwReturn << std::endl;
			return false;
		}

		// Get actual data with correct buffer size
		buffer = std::make_unique<BYTE[]>(bufferSize);
		dwReturn = GetExtendedTcpTable(buffer.get(), &bufferSize, TRUE, ipVer, tableClass, 0);

		if (dwReturn != NO_ERROR)
		{
			std::cerr << "GetExtendedTcpTable error 0x" << std::hex << dwReturn << std::endl;
			return false;
		}
		return true;
	}

	bool GetUdpConnectionTable(IpVersion ipVersion, UDP_TABLE_CLASS tableClass, std::unique_ptr<BYTE[]>& buffer)
	{
		unsigned long bufferSize = 0;
		ULONG ipVer = ipVersion == IpVersion::IPv4 ? AF_INET : AF_INET6;

		DWORD dwReturn = GetExtendedUdpTable(nullptr, &bufferSize, TRUE, ipVer, tableClass, 0);
		if (dwReturn != ERROR_INSUFFICIENT_BUFFER)
		{
			std::cerr << "GetExtendedUdpTable error 0x" << std::hex << dwReturn << std::endl;
			return false;
		}

		// Get actual data with correct buffer size
		buffer = std::make_unique<BYTE[]>(bufferSize);
		dwReturn = GetExtendedUdpTable(buffer.get(), &bufferSize, TRUE, ipVer, tableClass, 0);
		if (dwReturn != NO_ERROR)
		{
			std::cerr << "GetExtendedUdpTable error 0x" << std::hex << dwReturn << std::endl;
			return false;
		}
		return true;
	}

	std::wstring StateToString(DWORD state)
	{
		switch (state)
		{
		case MIB_TCP_STATE_CLOSED:
			return std::wstring(L"CLOSED");
			break;
		case MIB_TCP_STATE_LISTEN:
			return std::wstring(L"LISTEN");
			break;
		case MIB_TCP_STATE_SYN_SENT:
			return std::wstring(L"SYN-SENT");
			break;
		case MIB_TCP_STATE_SYN_RCVD:
			return std::wstring(L"SYN-RECEIVED");
			break;
		case MIB_TCP_STATE_ESTAB:
			return std::wstring(L"ESTABLISHED");
			break;
		case MIB_TCP_STATE_FIN_WAIT1:
			return std::wstring(L"FIN-WAIT-1");
			break;
		case MIB_TCP_STATE_FIN_WAIT2:
			return std::wstring(L"FIN-WAIT-2");
			break;
		case MIB_TCP_STATE_CLOSE_WAIT:
			return std::wstring(L"CLOSE-WAIT");
			break;
		case MIB_TCP_STATE_CLOSING:
			return std::wstring(L"CLOSING");
			break;
		case MIB_TCP_STATE_LAST_ACK:
			return std::wstring(L"LAST-ACK");
			break;
		case MIB_TCP_STATE_TIME_WAIT:
			return std::wstring(L"TIME-WAIT");
			break;
		case MIB_TCP_STATE_DELETE_TCB:
			return std::wstring(L"DELETE-TCB");
			break;
		default:
			return std::wstring(L"UNKNOWN");
			break;
		}
	}

	std::vector<ConnectionInfo> GetTcpConnectionsStatusIPv4()
	{
		std::vector<ConnectionInfo> connections;
		std::unique_ptr<BYTE[]> tcpTableBuffer;

		if (GetTcpConnectionTable(IpVersion::IPv4, TCP_TABLE_OWNER_PID_ALL, tcpTableBuffer))
		{
			PMIB_TCPTABLE_OWNER_PID pTcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(tcpTableBuffer.get());
			for (unsigned int i = 0; i < pTcpTable->dwNumEntries; i++)
			{
				MIB_TCPROW_OWNER_PID entry = pTcpTable->table[i];
				ConnectionInfo connectionInfo{ 0 };
				connectionInfo.protocol = ProtocolType::TCP;
				connectionInfo.ipVersion = IpVersion::IPv4;
				connectionInfo.ownerPid = entry.dwOwningPid;
				connectionInfo.localAddressIPv4 = entry.dwLocalAddr;
				connectionInfo.localAddressStr = DwordToIpString(entry.dwLocalAddr);
				connectionInfo.localPort = ntohs(static_cast<unsigned short>(entry.dwLocalPort));
				connectionInfo.remoteAddressIPv4 = entry.dwRemoteAddr;
				connectionInfo.remoteAddressStr = DwordToIpString(entry.dwRemoteAddr);
				connectionInfo.remotePort = ntohs(static_cast<unsigned short>(entry.dwRemotePort));
				connectionInfo.state = StateToString(entry.dwState);
				connections.push_back(connectionInfo);
			}
		}
		else
		{
			std::cerr << "GetTcpConnectionsStatusIPv4 error\n";
		}

		return connections;
	}

	std::vector<ConnectionInfo> GetTcpConnectionsStatusIPv6()
	{
		std::vector<ConnectionInfo> connections;
		std::unique_ptr<BYTE[]> tcpTableBuffer;

		if (GetTcpConnectionTable(IpVersion::IPv6, TCP_TABLE_OWNER_PID_ALL, tcpTableBuffer))
		{
			PMIB_TCP6TABLE_OWNER_PID pTcpTable = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(tcpTableBuffer.get());
			for (unsigned int i = 0; i < pTcpTable->dwNumEntries; i++)
			{
				MIB_TCP6ROW_OWNER_PID entry = pTcpTable->table[i];
				ConnectionInfo connectionInfo{ 0 };
				connectionInfo.protocol = ProtocolType::TCP;
				connectionInfo.ipVersion = IpVersion::IPv6;
				connectionInfo.ownerPid = entry.dwOwningPid;
				memcpy(connectionInfo.localAddressIPv6, entry.ucLocalAddr, 16);
				connectionInfo.localAddressStr = IPv6ToIpString(entry.ucLocalAddr);
				connectionInfo.localPort = ntohs(static_cast<unsigned short>(entry.dwLocalPort));
				memcpy(connectionInfo.remoteAddressIPv6, entry.ucRemoteAddr, 16);
				connectionInfo.remoteAddressStr = IPv6ToIpString(entry.ucRemoteAddr);
				connectionInfo.remotePort = ntohs(static_cast<unsigned short>(entry.dwRemotePort));
				connectionInfo.state = StateToString(entry.dwState);
				connections.push_back(connectionInfo);
			}
		}
		else
		{
			std::cerr << "GetTcpConnectionsStatusIPv6 error\n";
		}

		return connections;
	}

	std::vector<ConnectionInfo> GetUdpConnectionsStatusIPv4()
	{
		std::vector<ConnectionInfo> connections;
		std::unique_ptr<BYTE[]> udpTableBuffer;
		
		if (GetUdpConnectionTable(IpVersion::IPv4, UDP_TABLE_OWNER_PID, udpTableBuffer))
		{
			PMIB_UDPTABLE_OWNER_PID pUdpTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(udpTableBuffer.get());
			for (unsigned int i = 0; i < pUdpTable->dwNumEntries; i++)
			{
				MIB_UDPROW_OWNER_PID entry = pUdpTable->table[i];
				ConnectionInfo connectionInfo{ 0 };
				connectionInfo.protocol = ProtocolType::UDP;
				connectionInfo.ipVersion = IpVersion::IPv4;
				connectionInfo.ownerPid = entry.dwOwningPid;
				connectionInfo.localAddressIPv4 = entry.dwLocalAddr;
				connectionInfo.localAddressStr = DwordToIpString(entry.dwLocalAddr);
				connectionInfo.localPort = ntohs(static_cast<unsigned short>(entry.dwLocalPort));
				connectionInfo.remoteAddressIPv4 = 0;
				connectionInfo.remoteAddressStr = L"*";
				connectionInfo.remotePort = 0;
				connectionInfo.state = L"";
				connections.push_back(connectionInfo);
			}
		}
		else
		{
			std::cerr << "GetUdpConnectionsStatusIPv4 error\n";
		}

		return connections;
	}

	std::vector<ConnectionInfo> GetUdpConnectionsStatusIPv6()
	{
		std::vector<ConnectionInfo> connections;
		std::unique_ptr<BYTE[]> udpTableBuffer;

		if (GetUdpConnectionTable(IpVersion::IPv6, UDP_TABLE_OWNER_PID, udpTableBuffer))
		{
			PMIB_UDP6TABLE_OWNER_PID pUdpTable = reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(udpTableBuffer.get());
			for (unsigned int i = 0; i < pUdpTable->dwNumEntries; i++)
			{
				MIB_UDP6ROW_OWNER_PID entry = pUdpTable->table[i];
				ConnectionInfo connectionInfo{ 0 };
				connectionInfo.protocol = ProtocolType::UDP;
				connectionInfo.ipVersion = IpVersion::IPv6;
				connectionInfo.ownerPid = entry.dwOwningPid;
				memcpy(connectionInfo.localAddressIPv6, entry.ucLocalAddr, 16);
				connectionInfo.localAddressStr = IPv6ToIpString(entry.ucLocalAddr);
				connectionInfo.localPort = ntohs(static_cast<unsigned short>(entry.dwLocalPort));
				ZeroMemory(connectionInfo.remoteAddressIPv6, 16);
				connectionInfo.remoteAddressStr = L"*";
				connectionInfo.remotePort = 0;
				connectionInfo.state = L"";
				connections.push_back(connectionInfo);
			}
		}
		else
		{
			std::cerr << "GetUdpConnectionsStatusIPv6 error\n";
		}

		return connections;
	}
}

std::vector<ConnectionInfo> GetConnectionsStatus()
{
	std::vector<ConnectionInfo> tcpConnections = GetTcpConnectionsStatusIPv4();
	std::vector<ConnectionInfo> tcpConnectionsIPv6 = GetTcpConnectionsStatusIPv6();
	std::vector<ConnectionInfo> udpConnections = GetUdpConnectionsStatusIPv4();
	std::vector<ConnectionInfo> udpConnectionsIPv6 = GetUdpConnectionsStatusIPv6();
	tcpConnections.insert(tcpConnections.end(), tcpConnectionsIPv6.begin(), tcpConnectionsIPv6.end());
	tcpConnections.insert(tcpConnections.end(), udpConnections.begin(), udpConnections.end());
	tcpConnections.insert(tcpConnections.end(), udpConnectionsIPv6.begin(), udpConnectionsIPv6.end());

	return tcpConnections;
}