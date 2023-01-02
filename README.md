# WinPOCs
A collection of POCs for Windows to serve as reference for other projects and security research.

- DllInjection: The classic way to inject a DLL in a running process. It writes the DLL path in the target process' memory and starts a remote thread to call LoadLibraryA.
- CLRDetection: Detects installed CLR versions in the machine or CLR versions running in a target process.
