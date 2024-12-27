#include "utils.h"


char my_tolower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}


wchar_t my_towlower(wchar_t c)
{
    if (c >= L'A' && c <= L'Z') {
        return c + (L'a' - L'A');
    }
    return c;
}

size_t my_wcslen(const wchar_t* s)
{
    const wchar_t* p = s;
    while (*p) {
        p++;
    }
    return p - s;
}

wchar_t* my_wcschr(const wchar_t* s, wchar_t c) {
    while (*s) {
        if (*s == c) {
            return (wchar_t*)s;
        }
        s++;
    }
    return NULL;
}

wchar_t* my_wcsncpy(wchar_t* dest, const wchar_t* src, size_t n)
{
    wchar_t* d = dest;
    const wchar_t* s = src;
    size_t i;

    for (i = 0; i < n && *s; i++) {
        *d++ = *s++;
    }

    for (; i < n; i++) {
        *d++ = L'\0';
    }
    return dest;
}

int _wcscmp(const wchar_t* str1, const wchar_t* str2)
{
    while (*str1 && (*str1 == *str2))
    {
        str1++;
        str2++;
    }
    return *str1 - *str2;
}

int StringCompareIW(const wchar_t* s1, const wchar_t* s2)
{
    int i = 0;
    while (s1[i] != L'\0' && s2[i] != L'\0')
    {
        if (my_towlower(s1[i]) != my_towlower(s2[i]))
        {
            return my_towlower(s1[i]) - my_towlower(s2[i]);
        }
        i++;
    }

    return s1[i] - s2[i];
}

int StringCompareIA(const char* s1, const char* s2)
{
    int i = 0;
    while (s1[i] != '\0' && s2[i] != '\0') {
        if (my_tolower(s1[i]) != my_tolower(s2[i])) {
            return my_tolower(s1[i]) - my_tolower(s2[i]);
        }
        i++;
    }
    return s1[i] - s2[i];
}
