#pragma once

#include <stdio.h>

FILE* fopen_nc(const char* pchPath, const char* pchMode, unsigned long long userID, unsigned long long appID);
void remove_nc(const char* pchPath, unsigned long long userID, unsigned long long appID);
