#pragma once

#include <windows.h>

class Process
{
public:
	DWORD pid = 0;
	HANDLE handle = nullptr;

	Process(char* procName);
	~Process();

	bool Open(DWORD access = PROCESS_ALL_ACCESS);
	void Close();

	LPVOID AllocMemory(size_t size, LPVOID address = nullptr, DWORD flProtect = PAGE_EXECUTE_READWRITE);
	BOOL FreeMemory(LPVOID address);
	BOOL WriteMemory(LPVOID dest, BYTE* buffer, size_t size);
	// TODO: ReadMemory
};
