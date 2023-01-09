#include "CLRDetection.h"
#include <iostream>
#include "../Common/Process.h"
#include "../Common/Constants.h"

#pragma comment(lib, "mscoree.lib")

int main(int argc, char** argv)
{
	ICLRMetaHost* pMetaHost = NULL;
	IEnumUnknown* runtime;
	CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);

	bool success = false;
	if (argc != 2)
	{
		std::cout << "Installed runtimes:\n";
		pMetaHost->EnumerateInstalledRuntimes(&runtime);
		EnumerateRuntimes(&runtime);
		runtime->Release();
		success = true;
	}
	else
	{
		char processName[MAX_LENGTH];
		strncpy_s(processName, argv[1], MAX_LENGTH);

		Process* proc = new Process(processName);

		if (proc->Open())
		{
			std::cout << "Loaded runtimes in " << processName << ": " << std::endl;
			pMetaHost->EnumerateLoadedRuntimes(proc->handle, &runtime);
			EnumerateRuntimes(&runtime);
			runtime->Release();

			proc->Close();
			success = true;
		}
		else 
		{
			std::cerr << "OpenProccess error " << GetLastError() << std::endl;
		}
		delete proc;
	}
	pMetaHost->Release();

	if (success)
		return 0;
	return 1;
}