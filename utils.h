#pragma once
#include <stdio.h>

char my_tolower(char c);
wchar_t my_towlower(wchar_t c);
size_t my_wcslen(const wchar_t* s);
wchar_t* my_wcschr(const wchar_t* s, wchar_t c);
wchar_t* my_wcsncpy(wchar_t* dest, const wchar_t* src, size_t n);
int _wcscmp(const wchar_t* str1, const wchar_t* str2);
int StringCompareIW(const wchar_t* s1, const wchar_t* s2);
int StringCompareIA(const char* s1, const char* s2);