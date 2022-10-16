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

typedef int VmError;
typedef int VmReason;
typedef unsigned long long VmResult;
typedef unsigned long long VmCount;
typedef struct Vm Vm;
typedef struct VmConfig VmConfig;
typedef struct VmInterface VmInterface;

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

enum
{
    VmResultSuccess                     = 0,
    VmErrorNotImpl                      = -1,   /* not implemented */
    VmErrorInvalid                      = -2,   /* invalid use (e.g. invalid args) */
    VmErrorMemory                       = -3,   /* memory error (e.g. out of memory) */
    VmErrorHypervisor                   = -4,   /* hypervisor error (e.g. not present) */
    VmErrorInstance                     = -5,   /* instance error (e.g. cannot create) */
    VmErrorThread                       = -6,   /* thread error (e.g. cannot create) */
    VmErrorCpu                          = -7,   /* cpu error (e.g. cannot create) */
    VmErrorStop                         = -8,   /* stop processing */
};

static inline
VmResult VmMakeResult(VmReason Reason, VmError Error)
{
    return ((VmResult)Reason << 32) | (VmResult)Error;
}

static inline
VmError VmGetError(VmResult Result)
{
    return (VmError)Result;
}

static inline
VmReason VmGetReason(VmResult Result)
{
    return (VmReason)(Result >> 32);
}

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
