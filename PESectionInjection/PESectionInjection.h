#pragma once

#include "../Common/PE.h"

bool InjectSection(PE& file, std::string sectionName, BYTE* buffer, size_t bufferSize, std::string outPath);