#pragma once

#include <windows.h>
#include "../Common/Process.h"
#include "../Common/PE.h"

bool ManualMapDll(Process& proc, const char* dllPath);
bool ManualMapDll(Process& proc, PE& dll);
