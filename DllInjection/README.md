# DllInjection
## DLL injection

DLL injection is a technique used to inject code into a running process and is commonly used to extend or modify the original behavior of an application. This technique has a myriad of legitimate and malicious uses. The list below shows some examples:

- **Function hooking**: DLL injection can be used to intercept and redirect function calls inside a process. This can be useful to monitor or modify the functionality of an application.
- **Game mods and cheats**: By injecting custom code into a game process, players can alter the game behavior, add new features, or gain unfair advantages;
- **Antivirus software**: Some antivirus applications utilize DLL injection to monitor processes for malicious activity. By hooking functions and having code running inside all processes, an antivirus is able to detect and prevent threats more easily;
- **Malware**: Malware can utilize this technique to obtain code execution inside legitimate processes. This can help avoid detection, steal data, or obtain persistence in the system.

## How it works
This is one of the simplest forms of DLL injection. Here's how it is done in this project:

- Obtain the PID of the target process (`CreateToolhelp32Snapshot`);
- Get a handle to the target process (`OpenProcess`);
- Allocate memory in the target process (`VirtualAllocEx`);
- Write the full DLL path in the previously allocated memory region (`WriteProcessMemory`);
- Find the address of the function `LoadLibraryA` <sup>1</sup>;
- Create a thread in the target process, and make it call `LoadLibraryA` with a pointer to the DLL path as a parameter (`CreateRemoteThread`).

To unload a DLL from a remote process:

- Get a handle to the module (DLL) to be unloaded <sup>2</sup>;
- Create a thread in the target process, and make it call `FreeLibraryA` with the module handle as a parameter.

---
1 - `LoadLibraryA` is a function located in **Kernel32.dll**, and ideally, to find the address of the function in the target process, one would have to find the base address of the **kernel32.dll** module within the target process and add it to the offset of `LoadLibraryA`. HOWEVER, due to how ASLR works in Windows, this is unnecessary if the target process and the injector bitness are the same. In Windows, the same DLL is (almost) always loaded in the same virtual address in every process with the same bitness, so to find the address of `LoadLibraryA`, it is only necessary to call `GetProcAddress` inside the injector, and the resulting address will correspond to the `LoadLibraryA` address in the target process as well.

In case the injector and target process bitness are different, then the second approach to find the address of `LoadLibraryA` will not work. In this situation, one way to find the function's address in the remote process is by utilizing `CreateToolhelp32Snapshot` to enumerate the modules loaded in the process and finding the offset of `LoadLibraryA` using any **PE** analysis tool, such as Detect-It-Easy.

2 - If you take a look at the value of the handle returned by the function `GetModuleHandleA`, you will notice that it corresponds to the virtual address in which the module is loaded. This handle value seems to be valid even when `GetModuleHandleA` is not called. So, to get a handle to a target module, it is only necessary to find the base address of that module in the target process.