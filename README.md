# WinPOCs

A collection of POCs for Windows to serve as reference for other projects and security research.

- [DllInjection](DllInjection): The classic way to inject a DLL into a running process. It writes the DLL path in the target process' memory and starts a remote thread to call LoadLibraryA.
- [ManualMapping](ManualMapping): A technique to inject a DLL by manually mapping it into the target process. Since the injection is done manually, the DLL will not show up as a module, and there is no way to obtain a handle to the DLL (I think). It is often used in game hacking as it prevents the anti-cheat from detecting the injected DLL to a certain extent.
- [PythonCodeInjection](PythonCodeInjection): An injector to run python code in a process. It injects a pythonXX.dll, makes the process call Py_InitializeEx, and then makes it run code with PyRun_SimpleString.
- [IATHook](IATHook): One of the simplest ways of hooking functions. It works by overwriting the function pointer in the IAT with the address of the hook function.
- [CLRDetection](CLRDetection): Detects installed CLR versions in the machine or CLR versions running in a target process.
