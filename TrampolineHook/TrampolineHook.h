#pragma once

#include "../Common/Process.h"

bool InstallTrampolineHook(Process* proc, char* targetModule, char* targetFunction, char* hookDll, char* hookFunction);