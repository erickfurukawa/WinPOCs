# TrampolineHook

This project requires the Capstone disassembly framework. Download the binaries and set them up before compiling the project.

A trampoline hook is a technique used to intercept function calls and modify their behavior. It works by overwriting the first few instructions of the target function with a jump to a hook function. The trampoline is a newly allocated memory region containing the instructions of the original function that were overwritten, plus a jump to the remainder of the original function.

The trampoline hook is more powerful than the IAT hook since it can hook any function and can even be used to hook functions in the middle of their code. The downside of this technique is that it cannot be used to hook very small functions (less than 5 bytes) and can be very hard to implement.

## How it works
The trampoline hook implemented in this project consists of four different parts (x86 not implemented):
- Stub: A jump instruction 5 bytes in size. In x86, the stub is an absolute jump to a 4-byte address and is used to jump to the hook function. In x64, the stub is a relative jump to a 4-byte address offset and is used to jump to the relay. The stub must be as small as possible so that it can be used even in small functions.
- Relay: An absolute jump to the hook function. The relay must be placed at an address near the stub so that the 4-byte relative jump can reach it. Since an absolute jump instruction to an 8-byte immediate doesn't exist in x64, the relay must use registers to store the absolute address of the jump. It is important to not thrash any important register so that the original function's arguments are not modified.
- Hook function: The function that will be called instead of the original. In case the hook function wants to call the original one, it must make a call to the trampoline address instead, as the original function is hooked and that would cause an infinite loop.
- Trampoline: Contains the original instructions that were overwritten by the stub and an absolute jump to the rest of the original function. The original instructions need to be modified in case they are RIP relative.