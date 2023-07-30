# GhostWritingInjection

## Observations
This project requires ROP gadgets that may not be present on your machine. It might be necessary to adjust the functions that find and utilize the gadgets to make it work properly. 

While the ghost writing technique does not require process handles to work, they are still being used in this project to find base addresses of modules and process bitness. `CreateToolHelp32Snapshot` tries to open a handle to the process with the `PROCESS_VM_READ`  permission, and in case the process handles are being protected (let's say, by an anti-cheat or anti-malware driver), it will be necessary to find another way to get access to these information.

## Ghost writing
Ghost writing is a technique that can be used to write arbitrary data in a target process by utilizing thread handles instead of process handles. A few interesting Windows APIs that can be used with thread handles are listed:

- **SuspendThread**: Suspends the specified thread.
- **ResumeThread**: Resumes the specified thread.
- **GetThreadContext**: Retrieves the context (registers) of the specified thread.
- **SetThreadContext**: Sets the context (registers) of the specified thread.

These functions can be utilized to control the state and registers of a thread, and by carefully modifying them, it is possible to achieve arbitrary code execution with the help of some ROP (return-oriented programming) gadgets. The list of gadgets I used in this project is listed below:

- **Loop gadget**: Also called the *sink gadget*, it is the sequence of bytes `\xEB\xFE`, that corresponds to the instruction `jmp -2`. This instruction is essentially an infinite loop; an instruction that keeps jumping to itself. Every step in the ghost writing chain should return to the loop gadget to prevent the application from crashing.
- **Write gadget**: Any form of *write-what-where* gadget such as `mov [rcx], rdx; ret;`. Since we have control over every register, this can be used to write arbitrary data to an arbitrary address. The stack pointer must point to an address that contains the loop gadget address so that the thread keeps looping after the execution of the write gadget.
- **Push gadget**: Not really necessary, but I like to use it because then the write gadget doesn't have to use only non-volatile registers. The push gadget is a gadget that pushes a non-volatile register into the stack and returns, for example, `push rdi; ret;`. It is used to make the thread jump to the loop gadget. This is the first gadget to be called in the chain, so the register has to be non-volatile. In case the register is volatile and the thread is waiting on a `syscall` return, the register could get changed and that would ruin the ghost writing chain.

## Injecting a DLL with ghost writing
Being able to write arbitrary data with ghost writing, and controlling the thread's state and registers, injecting a DLL into the target process is not very complicated:

- Make the thread run `VirtualAlloc` to allocate memory: This is not strictly necessary. You can find any writable memory region and write data there, but I like doing it this way. To make the thread call `VirtualAlloc`, you have to consider the process bitness and adjust the stack and registers with the appropriate arguments. The stack arguments can be written with the write gadget, and the registers can be set with `SetThreadContext`.
- Write the DLL path in the newly allocated memory region: This can be achieved with the write gadget.
- Make the thread run `LoadLibraryA`: Just like calling `VirtualAlloc`, adjust the stack and registers appropriately.

If everything went right, we have just achieved arbitrary code execution in the target process without ever getting a process handle or writing into the process memory directly. It might be a good idea to restore the thread registers to their initial state so that the process can continue executing as if nothing had ever happened.