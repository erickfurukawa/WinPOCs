#include "Process.h"

DWORD GetPid(char* procName)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD pid = 0;

	// creates process snapshot
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		std::cerr << "CreateToolhelp32Snapshot error: " << GetLastError() << std::endl;
		return 0;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32); 
	if (!Process32First(hProcessSnap, &pe32))
	{
		std::cerr << "CreateToolhelp32Snapshot error: " << GetLastError() << std::endl;
		CloseHandle(hProcessSnap);
		return 0;
	}

	do // loops through processes
	{
		if (_strcmpi(procName, pe32.szExeFile) == 0) 
		{
			pid = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	if (!pid) {
		std::cerr << "Could not find process: " << procName << std::endl;
	}
	return pid;
}

void* AllocMem(HANDLE hProc, size_t size)
{
	void* addr = VirtualAllocEx(hProc, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!addr) {
		std::cerr << "VirtualAllocEx error: " << GetLastError() << std::endl;
	}
	return addr;
}

void WriteMem(HANDLE hProc, void* dest, BYTE* buffer, size_t size)
{
	WriteProcessMemory(hProc, dest, buffer, size, nullptr);
}