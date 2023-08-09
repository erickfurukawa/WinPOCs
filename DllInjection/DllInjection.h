#pragma once

#include <iostream>
#include <fstream>
#include "../Common/Constants.h"
#include "../Common/Process.h"
#include "../Common/PE.h"

// The thread handle must be closed by the caller
HANDLE InjectDll(Process& proc, const char* dllPath);
// The thread handle must be closed by the caller
HANDLE InjectDll(Process& proc, PE& dll);