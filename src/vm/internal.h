/**
 * @file vm/internal.h
 *
 * @copyright 2022 Bill Zissimopoulos
 */
/*
 * This file is part of VirtualMetal.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * Affero General Public License version 3 as published by the Free
 * Software Foundation.
 */

#ifndef VM_INTERNAL_H_INCLUDED
#define VM_INTERNAL_H_INCLUDED

#if defined(_WIN64)

#if defined(_M_X64)
#else
#error unknown architecture
#endif

#include <windows.h>
#include <fcntl.h>

/*
 * memory operations
 */

#undef RtlFillMemory
#undef RtlMoveMemory
NTSYSAPI VOID NTAPI RtlFillMemory(VOID *Destination, DWORD Length, BYTE Fill);
NTSYSAPI VOID NTAPI RtlMoveMemory(VOID *Destination, CONST VOID *Source, DWORD Length);

#pragma function(memset)
#pragma function(memcpy)
#pragma warning(push)
#pragma warning(disable:4163)           /* not available as an intrinsic function */
#pragma function(memmove)
#pragma warning(pop)
static inline
void *memset(void *dst, int val, size_t siz)
{
    RtlFillMemory(dst, (DWORD)siz, val);
    return dst;
}
static inline
void *memcpy(void *dst, const void *src, size_t siz)
{
    RtlMoveMemory(dst, src, (DWORD)siz);
    return dst;
}
static inline
void *memmove(void *dst, const void *src, size_t siz)
{
    RtlMoveMemory(dst, src, (DWORD)siz);
    return dst;
}

/*
 * malloc / free
 */

static inline
void *malloc(size_t Size)
{
    return HeapAlloc(GetProcessHeap(), 0, Size);
}
static inline
void *realloc(void *Pointer, size_t Size)
{
    return HeapReAlloc(GetProcessHeap(), 0, Pointer, Size);
}
static inline
void free(void *Pointer)
{
    if (0 != Pointer)
        HeapFree(GetProcessHeap(), 0, Pointer);
}

/*
 * open / close
 */

#define O_RDONLY                        _O_RDONLY
#define O_WRONLY                        _O_WRONLY
#define O_RDWR                          _O_RDWR
#define O_APPEND                        _O_APPEND
#define O_CREAT                         _O_CREAT
#define O_EXCL                          _O_EXCL
#define O_TRUNC                         _O_TRUNC

static inline
int open(const char *path, int oflag, ...)
{
    static DWORD da[] = { GENERIC_READ, GENERIC_WRITE, GENERIC_READ | GENERIC_WRITE, 0 };
    static DWORD cd[] = { OPEN_EXISTING, OPEN_ALWAYS, TRUNCATE_EXISTING, CREATE_ALWAYS };
    DWORD DesiredAccess = 0 == (oflag & _O_APPEND) ?
        da[oflag & (_O_RDONLY | _O_WRONLY | _O_RDWR)] :
        (da[oflag & (_O_RDONLY | _O_WRONLY | _O_RDWR)] & ~FILE_WRITE_DATA) | FILE_APPEND_DATA;
    DWORD CreationDisposition = (_O_CREAT | _O_EXCL) == (oflag & (_O_CREAT | _O_EXCL)) ?
        CREATE_NEW :
        cd[(oflag & (_O_CREAT | _O_TRUNC)) >> 8];
    return (int)(UINT_PTR)CreateFileA(path,
        DesiredAccess, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0/* default security */,
        CreationDisposition, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, 0);
}

static inline
int close(int fd)
{
    return CloseHandle((HANDLE)(UINT_PTR)fd) ? 0 : -1;
}

/*
 * startup
 */

#define EXEMAIN extern inline void mainCRTStartup(void)
inline void mainCRTStartup(void)
{
    PWSTR *ArgvW;
    int argc, argl;
    char **argv, *argp, *argendp;
    ArgvW = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (0 == ArgvW)
        ExitProcess(GetLastError());
    argl = 0;
    for (int i = 0; argc > i; i++)
        argl += WideCharToMultiByte(CP_UTF8, 0, ArgvW[i], -1, 0, 0, 0, 0);
    argv = malloc((argc + 1) * sizeof(char *) + argl);
    argp = (char *)argv + (argc + 1) * sizeof(char *);
    argendp = argp + argl;
    for (int i = 0; argc > i; i++)
    {
        argv[i] = argp;
        argp += WideCharToMultiByte(CP_UTF8, 0, ArgvW[i], -1, argp, (int)(argendp - argp), 0, 0);
    }
    argv[argc] = 0;
    LocalFree(ArgvW);
    int main(int argc, char **argv);
    ExitProcess(main(argc, argv));
}

#define LIBMAIN extern inline BOOL WINAPI _DllMainCRTStartup(HINSTANCE Instance, DWORD Reason, PVOID Reserved)
inline BOOL WINAPI _DllMainCRTStartup(HINSTANCE Instance, DWORD Reason, PVOID Reserved)
{
    return TRUE;
}

#elif defined(__linux__)

#if defined(__x86_64__)
#else
#error unknown architecture
#endif

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define EXEMAIN struct exemain_unused__ {}
#define LIBMAIN struct libmain_unused__ {}

#elif defined(__APPLE__)

#else

#error unknown platform

#endif

/*
 * string operations
 */

#define VM_INTERNAL_STRCMP(NAME, TYPE, CONV)\
    static inline\
    int NAME(const TYPE *s, const TYPE *t)\
    {\
        int v = 0;\
        while (0 == (v = (int)(CONV((unsigned)*s) - CONV((unsigned)*t))) && *t)\
            ++s, ++t;\
        return v;/*(0 < v) - (0 > v);*/\
    }
#define VM_INTERNAL_STRNCMP(NAME, TYPE, CONV)\
    static inline\
    int NAME(const TYPE *s, const TYPE *t, size_t n)\
    {\
        int v = 0;\
        const void *e = t + n;\
        while (e > (const void *)t && 0 == (v = (int)(CONV((unsigned)*s) - CONV((unsigned)*t))) && *t)\
            ++s, ++t;\
        return v;/*(0 < v) - (0 > v);*/\
    }
static inline
unsigned invariant_toupper(unsigned c)
{
    return c - 'a' <= 'z' - 'a' ? c & ~0x20U : c;
}
VM_INTERNAL_STRCMP(invariant_strcmp, char, )
VM_INTERNAL_STRCMP(invariant_stricmp, char, invariant_toupper)
VM_INTERNAL_STRNCMP(invariant_strncmp, char, )
VM_INTERNAL_STRNCMP(invariant_strnicmp, char, invariant_toupper)
#undef VM_INTERNAL_STRCMP
#undef VM_INTERNAL_STRNCMP

#define VM_INTERNAL_STRTOINT(NAME, CTYPE, ITYPE)\
    static inline\
    ITYPE NAME(const CTYPE *p, CTYPE **endp, unsigned base, int is_signed)\
    {\
        ITYPE v;\
        unsigned maxdig, maxalp;\
        int sign = +1;\
        if (is_signed)\
        {\
            if ('+' == *p)\
                p++;\
            else if ('-' == *p)\
                p++, sign = -1;\
        }\
        if (0 == base)\
        {\
            if ('0' == *p)\
            {\
                p++;\
                if ('x' == *p || 'X' == *p)\
                {\
                    p++;\
                    base = 16;\
                }\
                else\
                    base = 8;\
            }\
            else\
            {\
                base = 10;\
            }\
        }\
        maxdig = 10 < base ? 9 : base - 1;\
        maxalp = 10 < base ? base - 11 : 0;\
        for (v = 0; *p; p++)\
        {\
            unsigned c = (unsigned)*p;\
            if (c - '0' <= maxdig)\
                v = base * v + (c - '0');\
            else\
            {\
                c |= 0x20;\
                if (c - 'a' <= maxalp)\
                    v = base * v + (c - 'a') + 10;\
                else\
                    break;\
            }\
        }\
        if (0 != endp)\
            *endp = (CTYPE *)p;\
        return (ITYPE)sign * v;\
    }
VM_INTERNAL_STRTOINT(strtoullint, char, unsigned long long int)
#undef VM_INTERNAL_STRTOINT

#endif
