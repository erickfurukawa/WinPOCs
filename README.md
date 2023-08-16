# WinPOCs

A collection of POCs for Windows to serve as a reference for other projects and security research.

Many of the projects utilize techniques similar to those used by malware. It might be necessary to disable your antivirus to run them without any issues.

- [DllInjection](DllInjection): The classic way to inject a DLL into a running process. It writes the DLL path in the target process' memory and starts a remote thread to call `LoadLibraryA`. DLLs may also be unloaded from the target process in a similar way with `GetModuleHandle` and `FreeLibraryA`.
- [ManualMapping](ManualMapping): A technique to inject a DLL by manually mapping it into the target process. Since the injection is done manually, the DLL will not show up as a module, and there is no way to obtain a handle to the DLL (I think). It is often used in game hacking as it prevents the anti-cheat from detecting the injected DLL to a certain extent.
- [GhostWritingInjection](GhostWritingInjection): Ghost writing is a technique that allows writing arbitrary data in the target process without a process handle. Instead, it utilizes a thread handle and ROP gadgets to control the execution flow of a thread and achieve arbitrary code execution. This project injects a DLL into a target process by utilizing this technique.
- [PythonCodeInjection](PythonCodeInjection): An injector to run python code in a process. It injects a `pythonXX.dll`, makes the process call `Py_InitializeEx`, and then makes it run code with `PyRun_SimpleString`.
- [IATHook](IATHook): One of the simplest ways of hooking functions. It works by overwriting the function pointer in the IAT with the address of the hook function. Since it changes the IAT, the hook doesn't work for local functions, and it is only applied to a single module.
- [TrampolineHook](TrampolineHook): A technique used to hook functions by overwriting the first few instructions with a jump to the hook function. It is more powerful than the IAT hook since it can hook any function and affect all modules. My current implementation is not handling RIP relative instructions, and will likely crash if the original function is called.
- [ProxyDllGenerator](ProxyDllGenerator): Generates files to build a proxy DLL. Can be used to hook functions.
- [PESectionInjection](PESectionInjection): Inject a new executable section in a PE file.
- [TokenPrivileges](TokenPrivileges): List or enable privileges of a process token.
- [DotnetParser](DotnetParser): Given a .NET binary, outputs a JSON with some .NET metadata.
- [CLRDetection](CLRDetection): Detects installed CLR versions in the machine or CLR versions running in a target process.
- DotnetDllInjection:
	- [DotnetDllInjection](DotnetDllInjection/DotnetDllInjection): Injects a managed DLL into a process. Needs to be used with the `DotnetDllLoader` DLL.
	- [DotnetDllLoader](DotnetDllInjection/DotnetDllLoader): A native DLL used as a helper to inject a managed DLL in a process. It loads the .NET runtime, loads the managed DLL, and runs a method from it.
- CSCodeInjection:
	- [CSCodeInjectionServer](CSCodeInjection/CSCodeInjectionServer): A DLL to be injected into a process to run C# code. It receives the code via sockets listening on localhost, compiles the code, and executes it.
	- [CSCodeInjectionClient](CSCodeInjection/CSCodeInjectionClient): A simple client that sends the contents of a file via sockets. Meant to be used to send C# code to `CSCodeInjectionServer`.
- [DotnetHook](DotnetHook): Helper classes to aid in function hooking and reflection in .NET. To hook a function in an external process, create a DLL using the helper classes and inject it with `DotnetDllInjection`.
