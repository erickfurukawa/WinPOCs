#include <iostream>
#include <metahost.h>
#include "../Common/Process.h"
#include "../Common/Constants.h"

#pragma comment(lib, "mscoree.lib")

void EnumerateRuntimes(IEnumUnknown** runtime);

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

void EnumerateRuntimes(IEnumUnknown** runtime)
{
	IUnknown* enumRuntime = nullptr;
	ICLRRuntimeInfo* runtimeInfo = nullptr;
	WCHAR frameworkName[2048];
	DWORD bytes = 1024;

	while ((*runtime)->Next(1, &enumRuntime, 0) == S_OK)
	{
		if (enumRuntime->QueryInterface<ICLRRuntimeInfo>(&runtimeInfo) == S_OK)
		{
			if (runtimeInfo != NULL)
			{
				runtimeInfo->GetVersionString(frameworkName, &bytes);
				std::wcout << frameworkName << std::endl;
				runtimeInfo->Release();
			}
		}
	}
	
}