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

	if (argc != 2)
	{
		std::cout << "Installed runtimes:\n";
		pMetaHost->EnumerateInstalledRuntimes(&runtime);
		EnumerateRuntimes(&runtime);
	}
	else
	{
		char processName[MAX_LENGTH];
		strncpy_s(processName, argv[1], MAX_LENGTH);

		Process proc = Process(processName);

		if (!proc.Open())
		{
			std::cerr << "OpenProccess error " << GetLastError() << std::endl;
			return 1;
		}

		std::cout << "Loaded runtimes in " << processName << ": " << std::endl;;
		pMetaHost->EnumerateLoadedRuntimes(proc.handle, &runtime);
		EnumerateRuntimes(&runtime);
		
		proc.Close();
	}
	runtime->Release();
	pMetaHost->Release();

	return 0;
}