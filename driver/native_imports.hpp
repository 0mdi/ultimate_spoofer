#pragma once
#include "hash.hpp"

uintptr_t FindModule(hash64_t moduleHash, size_t* moduleSize = nullptr);
uintptr_t GetExportHash(uintptr_t module, hash64_t hash);

void* riCopyMem(void* dest, const void* src, size_t count);
char* riAnsiConvert(const wchar_t* wstr);
int riStrLength(const char* s);
int riToLower(int ch);
int riStricmp(const char* s1, const char* s2);
void riStrCopy(char* buffer, const char* other);
char* riStrstr(const char* str, const char* substring);