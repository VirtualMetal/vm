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

#if defined(_MSC_VER) && defined(_M_X64)
#elif defined(__GNUC__) && defined(__x86_64__)
#else
#error unknown architecture
#endif

#if defined(_WIN64)
#elif defined(__linux__)
#else
#error unknown platform
#endif

#include <vm/vm.h>
#include <arch/arch.h>

#if defined(_WIN64)

#include <windows.h>

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
 * POSIX-like file I/O
 */

#undef errno
#define errno                           GetLastError()

#define STDIN_FILENO                    ((int)(UINT_PTR)GetStdHandle(STD_INPUT_HANDLE))
#define STDOUT_FILENO                   ((int)(UINT_PTR)GetStdHandle(STD_OUTPUT_HANDLE))
#define STDERR_FILENO                   ((int)(UINT_PTR)GetStdHandle(STD_ERROR_HANDLE))

/* O_* flags - compatible with MSVC */
#define O_RDONLY                        0x0000
#define O_WRONLY                        0x0001
#define O_RDWR                          0x0002
#define O_APPEND                        0x0008
#define O_CREAT                         0x0100
#define O_EXCL                          0x0400
#define O_TRUNC                         0x0200

typedef SSIZE_T ssize_t;
typedef SSIZE_T off_t;

/* struct stat */
struct timespec
{
    long long tv_sec;
    long long tv_nsec;
};
struct stat
{
    unsigned st_dev;
    unsigned long long st_ino;
    unsigned st_mode;
    unsigned short st_nlink;
    unsigned st_uid;
    unsigned st_gid;
    unsigned st_rdev;
    off_t st_size;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    int st_blksize;
    long long st_blocks;
};

static inline
int open(const char *path, int oflag, ...)
{
    static DWORD da[] = { GENERIC_READ, GENERIC_WRITE, GENERIC_READ | GENERIC_WRITE, 0 };
    static DWORD cd[] = { OPEN_EXISTING, OPEN_ALWAYS, TRUNCATE_EXISTING, CREATE_ALWAYS };
    DWORD DesiredAccess = 0 == (oflag & O_APPEND) ?
        da[oflag & (O_RDONLY | O_WRONLY | O_RDWR)] :
        (da[oflag & (O_RDONLY | O_WRONLY | O_RDWR)] & ~FILE_WRITE_DATA) | FILE_APPEND_DATA;
    DWORD CreationDisposition = (O_CREAT | O_EXCL) == (oflag & (O_CREAT | O_EXCL)) ?
        CREATE_NEW :
        cd[(oflag & (O_CREAT | O_TRUNC)) >> 8];
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

static inline
int fstat(int fd, struct stat *stbuf)
{
#define filetime_to_unixtime(FT, UT)    \
    FileTime = *(PUINT64)&FT - 116444736000000000ULL;\
    UT = (struct timespec){ .tv_sec = FileTime / 10000000, .tv_nsec = FileTime % 10000000 * 100 };

    HANDLE h = (HANDLE)(UINT_PTR)fd;
    BY_HANDLE_FILE_INFORMATION FileInfo;
    INT64 FileTime;

    if (!GetFileInformationByHandle(h, &FileInfo))
        return -1;

    memset(stbuf, 0, sizeof *stbuf);
    stbuf->st_ino = ((UINT64)FileInfo.nFileIndexHigh << 32) | ((UINT64)FileInfo.nFileIndexLow);
    stbuf->st_mode = 0777 |
        ((FileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 0040000/* S_IFDIR */ : 0);
    stbuf->st_nlink = (UINT16)FileInfo.nNumberOfLinks;
    stbuf->st_size = ((UINT64)FileInfo.nFileSizeHigh << 32) | ((UINT64)FileInfo.nFileSizeLow);
    filetime_to_unixtime(FileInfo.ftLastAccessTime, stbuf->st_atim);
    filetime_to_unixtime(FileInfo.ftLastWriteTime, stbuf->st_mtim);
    filetime_to_unixtime(FileInfo.ftLastWriteTime, stbuf->st_ctim);

    return 0;

#undef filetime_to_unixtime
}

static inline
ssize_t pread(int fd, void *buf, size_t nbyte, off_t offset)
{
    HANDLE h = (HANDLE)(UINT_PTR)fd;
    OVERLAPPED Overlapped = { 0 };
    DWORD BytesTransferred;
    Overlapped.Offset = (DWORD)offset;
    Overlapped.OffsetHigh = (DWORD)((size_t)offset >> 32);
    if (!ReadFile(h, buf, (DWORD)nbyte, &BytesTransferred, &Overlapped))
    {
        if (ERROR_HANDLE_EOF == GetLastError())
            return 0;
        return -1;
    }
    return BytesTransferred;
}

static inline
ssize_t pwrite(int fd, const void *buf, size_t nbyte, off_t offset)
{
    HANDLE h = (HANDLE)(UINT_PTR)fd;
    OVERLAPPED Overlapped = { 0 };
    DWORD BytesTransferred;
    Overlapped.Offset = (DWORD)offset;
    Overlapped.OffsetHigh = (DWORD)((size_t)offset >> 32);
    if (!WriteFile(h, buf, (DWORD)nbyte, &BytesTransferred, &Overlapped))
        return -1;
    return BytesTransferred;
}

static inline
ssize_t read(int fd, void *buf, size_t nbyte)
{
    return pread(fd, buf, nbyte, -1LL);
}

static inline
ssize_t write(int fd, const void *buf, size_t nbyte)
{
    return pwrite(fd, buf, nbyte, -1LL);
}

static inline
int unlink(const char *path)
{
    return DeleteFileA(path) ? 0 : -1;
}

/*
 * miscellaneous
 */

#define sprintf(...)                    wsprintfA(__VA_ARGS__)
#define vsprintf(...)                   wvsprintfA(__VA_ARGS__)

#pragma function(strlen)
static inline
size_t strlen(const char *s)
{
    return lstrlenA(s);
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

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define EXEMAIN struct exemain__unused__ {}
#define LIBMAIN struct libmain__unused__ {}

#endif

/*
 * bitmaps
 */

typedef unsigned long long bmap_t;

#define bmap_declcount(capacity)        (((capacity) + bmap__mask__() - 1) >> bmap__shift__())
#define bmap_capacity(bmap)             (sizeof(bmap) << 3)
#define bmap__shift__()                 (6)
#define bmap__mask__()                  (0x3f)

static inline
unsigned bmap_get(bmap_t *bmap, unsigned pos)
{
#if defined(_MSC_VER)
    return _bittest64(&bmap[pos >> bmap__shift__()], pos & bmap__mask__());
#elif defined(__GNUC__)
    return !!(bmap[pos >> bmap__shift__()] & ((bmap_t)1 << (pos & bmap__mask__())));
#endif
}

static inline
void bmap_set(bmap_t *bmap, unsigned pos, unsigned val)
{
    if (val)
        bmap[pos >> bmap__shift__()] |= ((bmap_t)1 << (pos & bmap__mask__()));
    else
        bmap[pos >> bmap__shift__()] &= ~((bmap_t)1 << (pos & bmap__mask__()));
}

static inline
unsigned bmap_popcount(bmap_t *bmap, unsigned capacity)
{
    unsigned res = 0;
    for (unsigned pos = 0, cnt = bmap_declcount(capacity); cnt > pos; pos++)
    {
        bmap_t bval = bmap[pos];
#if defined(_MSC_VER)
        res += (unsigned)__popcnt64(bval);
#elif defined(__GNUC__)
        res += (unsigned)__builtin_popcountll(bval);
#endif
    }
    return res;
}

static inline
unsigned bmap_find(bmap_t *bmap, unsigned capacity, unsigned val)
{
    for (unsigned idx = 0, cnt = bmap_declcount(capacity); cnt > idx; idx++)
    {
        bmap_t bval = val ? bmap[idx] : ~bmap[idx];
        unsigned bpos;
#if defined(_MSC_VER)
        if (_BitScanForward64(&bpos, bval))
            return (idx << bmap__shift__()) | bpos;
#elif defined(__GNUC__)
        if (0 != (bpos = (unsigned)__builtin_ffsll((long long)bval)))
            return (idx << bmap__shift__()) | (bpos - 1);
#endif
    }
    return ~0U;
}

/*
 * linked lists
 */

typedef struct list_link
{
    struct list_link *next, *prev;
} list_link_t;

static inline
void list_init(list_link_t *list)
{
    list->next = list;
    list->prev = list;
}

static inline
int list_is_empty(list_link_t *list)
{
    return list->next == list;
}

static inline
void list_insert_after(list_link_t *list, list_link_t *link)
{
    list_link_t *next = list->next;
    link->next = next;
    link->prev = list;
    next->prev = link;
    list->next = link;
}

static inline
void list_insert_before(list_link_t *list, list_link_t *link)
{
    list_link_t *prev = list->prev;
    link->next = list;
    link->prev = prev;
    prev->next = link;
    list->prev = link;
}

static inline
list_link_t *list_remove_after(list_link_t *list)
{
    list_link_t *link = list->next;
    list_link_t *next = link->next;
    list->next = next;
    next->prev = list;
    return link;
}

static inline
list_link_t *list_remove_before(list_link_t *list)
{
    list_link_t *link = list->prev;
    list_link_t *prev = link->prev;
    prev->next = list;
    list->prev = prev;
    return link;
}

static inline
void list_remove(list_link_t *link)
{
    list_link_t *next = link->next;
    list_link_t *prev = link->prev;
    next->prev = prev;
    prev->next = next;
}

#define list_traverse(i, dir, l)        \
    for (list_link_t *i = (l)->dir, *i##__list_temp__; i != (l); i = i##__list_temp__)\
        if (i##__list_temp__ = i->dir, 0) ; else

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
    ITYPE NAME(const CTYPE *p, CTYPE **endp, int base)\
    {\
        ITYPE v;\
        int maxdig, maxalp, sign = +1;\
        if (0 > base)\
        {\
            base = -base;\
            if ('+' == *p)\
                p++;\
            else if ('-' == *p)\
                p++, sign = -1;\
        }\
        if (2 > base)\
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
        maxdig = 10 < base ? '9' : (base - 1) + '0';\
        maxalp = 10 < base ? (base - 1 - 10) + 'a' : 0;\
        for (v = 0; *p; p++)\
        {\
            int c = *p;\
            if ('0' <= c && c <= maxdig)\
                v = (ITYPE)base * v + (ITYPE)(c - '0');\
            else\
            {\
                c |= 0x20;\
                if ('a' <= c && c <= maxalp)\
                    v = (ITYPE)base * v + (ITYPE)(c - 'a') + 10;\
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
