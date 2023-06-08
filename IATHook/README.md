# IATHook

IAT hook is a technique used to intercept external function calls made from a module (`.dll` or `.exe` file loaded in a process). It involves overwriting the entries in the Import Address Table (IAT), which contains pointers to external functions used by the module. By changing the addresses in the IAT, the hook can redirect function calls to different addresses, allowing for custom code to be executed instead of the original function.
Despite being relatively easy to do, an IAT hook can only be applied to functions located in the IAT. Local functions and dynamically loaded functions cannot be intercepted by this method.

## How it works
This project only hooks in the IAT of the main module. Here is how it is done:
- Inject a DLL with the hook function in the target process (see [DllInjection](DllInjection))
- Get the base address of the main module (`CreateToolhelp32Snapshot`)
- Find the RVA of the target function IAT entry in the main module (by parsing the PE format)
- Get the address of the hook function
	  This can be done with `GetProcAddress` but in this project I opted to parse the PE format to find the exported function RVA and add it to the hook DLL base address.
- Change the memory protection of the IAT entry (`VirtualProtectEx`)
- Overwrite the IAT entry with the address of the hook function (`WriteProcessMemory`)