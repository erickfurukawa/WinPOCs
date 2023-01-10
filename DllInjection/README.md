# DllInjection

The classic way to inject a DLL into a running process.

## How it works

This is one of the simplest forms of DLL injection. Here's how it is done in this project:
- Obtain the PID of the target process (**CreateToolhelp32Snapshot**)
- Get a handle of the target process (**OpenProcess**)
- Allocate memory in the target process (**VirtualAllocEx**)
- Write the full DLL path in the previously allocated memory region (**WriteProcessMemory**)
- Find the address of the function **LoadLibraryA** \*
- Create a thread in the target process, and make it call LoadLibraryA with a pointer to the DLL path as a parameter (**CreateRemoteThread**)

\* **LoadLibraryA** is a function located in **Kernel32.dll**, and ideally, to find the address of **LoadLibraryA** in the target process, one would have to find the base address of the **Kernel32.dll** module in the target process and add it to the offset of **LoadLibraryA**. HOWEVER, due to how ASLR works in Windows, this is unnecessary. The same **dll** is (almost) always loaded in the same base address in every process, and since our injector also has **Kernel32.dll** loaded by default, to find the address of **LoadLibraryA** in the target process, we just have to find the address of that function in our own process. I'm not going into details on why Windows ASLR works this way, but as far as I know, it is related to PIE, relocations, and shared memory.
