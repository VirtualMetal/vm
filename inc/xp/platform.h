/**
 * @file xp/platform.h
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

#ifndef XP_PLATFORM_H_INCLUDED
#define XP_PLATFORM_H_INCLUDED

#if defined(_WIN64)

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include <stdint.h>

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
int chdir(const char *path)
{
    return SetCurrentDirectoryA(path) ? 0 : -1;
}

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
    HANDLE h = (HANDLE)(UINT_PTR)fd;
    DWORD BytesTransferred;
    if (!ReadFile(h, buf, (DWORD)nbyte, &BytesTransferred, 0))
    {
        if (ERROR_HANDLE_EOF == GetLastError())
            return 0;
        return -1;
    }
    return BytesTransferred;
}

static inline
ssize_t write(int fd, const void *buf, size_t nbyte)
{
    HANDLE h = (HANDLE)(UINT_PTR)fd;
    DWORD BytesTransferred;
    if (!WriteFile(h, buf, (DWORD)nbyte, &BytesTransferred, 0))
        return -1;
    return BytesTransferred;
}

static inline
int unlink(const char *path)
{
    return DeleteFileA(path) ? 0 : -1;
}

/*
 * POSIX-like threads
 */

typedef HANDLE pthread_t;
typedef struct pthread_attr pthread_attr_t;

static inline
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
    void *(*start_routine)(void *), void *arg)
{
    /*
     * On Win64 the __stdcall and __cdecl calling conventions are the same.
     * This allows us to safely cast the start_routine to PTHREAD_START_ROUTINE.
     * There is a mismatch on the return type of start_routine (void *) and
     * PTHREAD_START_ROUTINE (DWORD). However a DWORD fits in a void *, so
     * I am going to ignore this! Just don't return a full void * from start_routine
     * and expect it to work.
     */
#if !defined(_INC_PROCESS)
    *thread = CreateThread(0, 0, (PTHREAD_START_ROUTINE)start_routine, arg, 0, 0);
#else
    *thread = (HANDLE)_beginthreadex(0, 0, (PTHREAD_START_ROUTINE)start_routine, arg, 0, 0);
#endif
    return *thread ? 0 : GetLastError();
}

static inline
int pthread_join(pthread_t thread, void **retval)
{
    DWORD ExitCode;
    WaitForSingleObject(thread, INFINITE);
    if (0 != retval)
    {
        GetExitCodeThread(thread, &ExitCode);
        *(PDWORD)retval = ExitCode;
    }
    CloseHandle(thread);
    return 0;
}

static inline
int pthread_detach(pthread_t thread)
{
    CloseHandle(thread);
    return 0;
}

static inline
void pthread_exit(void *retval)
{
#if !defined(_INC_PROCESS)
    ExitThread((DWORD)(UINT_PTR)retval);
#else
    _endthreadex((DWORD)(UINT_PTR)retval);
#endif
}

/*
 * POSIX-like synchronization
 */

typedef SRWLOCK pthread_mutex_t;
typedef struct pthread_mutexattr pthread_mutexattr_t;
#define PTHREAD_MUTEX_INITIALIZER       SRWLOCK_INIT

static inline
int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr)
{
    return InitializeSRWLock(mutex), 0;
}

static inline
int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    return 0;
}

static inline
int pthread_mutex_lock(pthread_mutex_t *mutex)
{
    return AcquireSRWLockExclusive(mutex), 0;
}

static inline
int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
    return TryAcquireSRWLockExclusive(mutex) ? 0 : ERROR_BUSY;
}

static inline
int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    return ReleaseSRWLockExclusive(mutex), 0;
}

typedef CONDITION_VARIABLE pthread_cond_t;
typedef struct pthread_condattr pthread_condattr_t;
#define PTHREAD_COND_INITIALIZER        CONDITION_VARIABLE_INIT

static inline
int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr)
{
    return InitializeConditionVariable(cond), 0;
}

static inline
int pthread_cond_destroy(pthread_cond_t *cond)
{
    return 0;
}

static inline
int pthread_cond_signal(pthread_cond_t *cond)
{
    return WakeConditionVariable(cond), 0;
}

static inline
int pthread_cond_broadcast(pthread_cond_t *cond)
{
    return WakeAllConditionVariable(cond), 0;
}

static inline
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    return SleepConditionVariableSRW(cond, mutex, INFINITE, 0);
}

/*
 * dlopen/dlsym/dlclose
 */

#define RTLD_NOW                        0
#define RTLD_LOCAL                      0

static inline
void *dlopen(const char *path, int flags)
{
    return LoadLibraryA(path);
}

static inline
int dlclose(void *handle)
{
    return FreeLibrary(handle) ? 0 : -1;
}

static inline
void *dlsym(void *handle, const char *sym)
{
    return GetProcAddress(handle, sym);
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

static inline
int getpagesize(void)
{
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    return sys_info.dwPageSize;
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
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
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
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

/*
 * miscellaneous
 */

/* sprintf max buffer size is 1024 for compatibility with wsprintfA */
#define sprintf(...)                    sprintf_1024(__VA_ARGS__)
#define vsprintf(...)                   vsprintf_1024(__VA_ARGS__)
static inline
int sprintf_1024(char *buf, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int res = vsnprintf(buf, 1024, fmt, ap);
    va_end(ap);
    return res;
}
static inline
int vsprintf_1024(char *buf, const char *fmt, va_list ap)
{
    return vsnprintf(buf, 1024, fmt, ap);
}

#define EXEMAIN struct exemain__unused__ {}
#define LIBMAIN struct libmain__unused__ {}

#endif

#endif
