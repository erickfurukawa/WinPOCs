#pragma once

#include <string>

void ThrowException(std::string msg);

void ThrowException(char* msg);

bool FileExists(char* fileName);