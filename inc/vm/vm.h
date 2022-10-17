/**
 * @file vm/vm.h
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

#ifndef VM_VM_H_INCLUDED
#define VM_VM_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

typedef long long VmResult;
typedef int VmReason;

#define VmResultSuccess                 ((VmResult)0)
#define VmErrorNotImpl                  ((VmResult)-1LL<<32)    /* not implemented */
#define VmErrorInvalid                  ((VmResult)-2LL<<32)    /* invalid use (e.g. invalid args) */
#define VmErrorMemory                   ((VmResult)-3LL<<32)    /* memory error (e.g. out of memory) */
#define VmErrorHypervisor               ((VmResult)-4LL<<32)    /* hypervisor error (e.g. not present) */
#define VmErrorInstance                 ((VmResult)-5LL<<32)    /* instance error (e.g. cannot create) */
#define VmErrorThread                   ((VmResult)-6LL<<32)    /* thread error (e.g. cannot create) */
#define VmErrorCpu                      ((VmResult)-7LL<<32)    /* cpu error (e.g. cannot create) */
#define VmErrorStop                     ((VmResult)-8LL<<32)    /* stop processing */

static inline
VmResult VmMakeResult(VmResult Error, VmReason Reason)
{
    return Error | (VmResult)(unsigned)Reason;
}

static inline
VmResult VmGetError(VmResult Result)
{
    return Result & (VmResult)0xffffffff00000000ULL;
}

static inline
VmReason VmGetReason(VmResult Result)
{
    return (VmReason)Result;
}

typedef struct Vm Vm;
typedef struct VmConfig VmConfig;
typedef struct VmInterface VmInterface;
typedef unsigned long long VmCount;

struct VmConfig
{
    VmInterface *Interface;
    VmCount CpuCount;
    VmCount MemorySize;

    VmCount Reserved[61];
};

struct VmInterface
{
    VmResult (*IoPort)();
    VmResult (*Memory)();

    VmResult (*Reserved[30])();
};

VmResult VmCreate(const VmConfig *Config, Vm **PInstance);
VmResult VmDelete(Vm *Instance);
VmResult VmSetDebugLog(Vm *Instance, unsigned Flags);
VmResult VmStartDispatcher(Vm *Instance);
VmResult VmWaitDispatcher(Vm *Instance);
VmResult VmStopDispatcher(Vm *Instance);

#ifdef __cplusplus
}
#endif

#endif
