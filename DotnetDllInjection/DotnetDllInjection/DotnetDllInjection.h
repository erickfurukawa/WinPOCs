#pragma once

#include "../../Common/Process.h"
#include "../../Common/PE.h"

bool InjectDotnetDll(Process& proc, const char* dllPath, const char* methodName, const char* argument);
bool InjectDotnetDll(Process& proc, PE& dll, const char* methodName, const char* argument);