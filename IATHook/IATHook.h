#pragma once

#include "../Common/Process.h"

bool InstallIATHook(Process* proc, char* targetModule, char* targetFunction, char* hookDll, char* hookFunction);