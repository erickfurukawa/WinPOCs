#pragma once

#include <iostream>
#include <fstream>
#include "../Common/Constants.h"
#include "../Common/Process.h"
#include "../Common/PE.h"

// The thread handle must be closed by the caller
HANDLE InjectDll(Process& proc, char* dllPath);
// The thread handle must be closed by the caller
HANDLE InjectDll(Process& proc, PE& dll);
// TODO: remove after changing all projects to stop using Process pointers
HANDLE InjectDll(Process* proc, char* dllPath);