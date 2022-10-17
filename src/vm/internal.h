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

#include <windows.h>

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

#pragma function(strcmp)
static inline
int strcmp(const char *s1, const char *s2)
{
    return lstrcmpA(s1, s2);
}

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

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define EXEMAIN struct exemain_unused__ {}
#define LIBMAIN struct libmain_unused__ {}

#elif defined(__APPLE__)

#else

#error unknown platform

#endif

#endif
