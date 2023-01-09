#pragma once

#include <iostream>
#include <fstream>
#include "../Common/Constants.h"
#include "../Common/Process.h"

HANDLE InjectDll(Process* proc, char* dllPath);
