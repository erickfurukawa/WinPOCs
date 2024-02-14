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

	std::vector<ConnectionInfo> GetTcpConnectionsStatus()
	{
		std::vector<ConnectionInfo> connections;
		PMIB_TCPTABLE2 pTcpTable;

		ULONG bufferSize = sizeof(MIB_TCPTABLE2);
		auto tcpTableBuffer = std::make_unique<BYTE[]>(bufferSize);
		pTcpTable = reinterpret_cast<PMIB_TCPTABLE2>(tcpTableBuffer.get());

		// Get size needed
		DWORD dwReturn = GetTcpTable2(pTcpTable, &bufferSize, TRUE);
		if (dwReturn != ERROR_INSUFFICIENT_BUFFER)
		{
			std::cerr << "GetTcpTable2 error 0x" << std::hex << dwReturn << std::endl;
			return connections;
		}

		// Get actual data with correct buffer size
		tcpTableBuffer = std::make_unique<BYTE[]>(bufferSize);
		pTcpTable = reinterpret_cast<PMIB_TCPTABLE2>(tcpTableBuffer.get());
		dwReturn = GetTcpTable2(pTcpTable, &bufferSize, TRUE);
		if (dwReturn == NO_ERROR)
		{
			for (unsigned int i = 0; i < pTcpTable->dwNumEntries; i++)
			{
				MIB_TCPROW2 entry = pTcpTable->table[i];
				ConnectionInfo connectionInfo{ 0 };
				connectionInfo.protocol = ProtocolType::TCP;
				connectionInfo.ownerPid = entry.dwOwningPid;
				connectionInfo.localAddress = entry.dwLocalAddr;
				connectionInfo.localAddressStr = DwordToIpString(entry.dwLocalAddr);
				connectionInfo.localPort = ntohs(static_cast<unsigned short>(entry.dwLocalPort));
				connectionInfo.remoteAddress = entry.dwRemoteAddr;
				connectionInfo.remoteAddressStr = DwordToIpString(entry.dwRemoteAddr);
				connectionInfo.remotePort = ntohs(static_cast<unsigned short>(entry.dwRemotePort));
				connectionInfo.state = StateToString(entry.dwState);
				connections.push_back(connectionInfo);
			}
		}
		else
		{
			std::cerr << "GetTcpTable2 error 0x" << std::hex << dwReturn << std::endl;
		}

		return connections;
	}

	std::vector<ConnectionInfo> GetUdpConnectionsStatus()
	{
		std::vector<ConnectionInfo> connections;
		PMIB_UDPTABLE_OWNER_PID  pUdpTable;

		ULONG bufferSize = sizeof(MIB_UDPTABLE_OWNER_PID);
		auto udpTableBuffer = std::make_unique<BYTE[]>(bufferSize);
		pUdpTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(udpTableBuffer.get());

		// Get size needed
		DWORD dwReturn = GetExtendedUdpTable(pUdpTable, &bufferSize, TRUE, AF_INET, UDP_TABLE_CLASS::UDP_TABLE_OWNER_PID, 0);
		if (dwReturn != ERROR_INSUFFICIENT_BUFFER)
		{
			std::cerr << "GetExtendedUdpTable error 0x" << std::hex << dwReturn << std::endl;
			return connections;
		}

		// Get actual data with correct buffer size
		udpTableBuffer = std::make_unique<BYTE[]>(bufferSize);
		pUdpTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(udpTableBuffer.get());
		dwReturn = GetExtendedUdpTable(pUdpTable, &bufferSize, TRUE, AF_INET, UDP_TABLE_CLASS::UDP_TABLE_OWNER_PID, 0);
		if (dwReturn == NO_ERROR)
		{
			for (unsigned int i = 0; i < pUdpTable->dwNumEntries; i++)
			{
				MIB_UDPROW_OWNER_PID entry = pUdpTable->table[i];
				ConnectionInfo connectionInfo{ 0 };
				connectionInfo.protocol = ProtocolType::UDP;
				connectionInfo.ownerPid = entry.dwOwningPid;
				connectionInfo.localAddress = entry.dwLocalAddr;
				connectionInfo.localAddressStr = DwordToIpString(entry.dwLocalAddr);
				connectionInfo.localPort = ntohs(static_cast<unsigned short>(entry.dwLocalPort));
				connectionInfo.remoteAddress = 0;
				connectionInfo.remoteAddressStr = L"*";
				connectionInfo.remotePort = 0;
				connectionInfo.state = L"";
				connections.push_back(connectionInfo);
			}
		}
		else
		{
			std::cerr << "GetExtendedUdpTable error 0x" << std::hex << dwReturn << std::endl;
		}

		return connections;
	}
}

std::vector<ConnectionInfo> GetConnectionsStatus()
{
	std::vector<ConnectionInfo> tcpConnections = GetTcpConnectionsStatus();
	std::vector<ConnectionInfo> udpConnections = GetUdpConnectionsStatus();
	tcpConnections.insert(tcpConnections.end(), udpConnections.begin(), udpConnections.end());

	return tcpConnections;
}