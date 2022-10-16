/**
 * @file vm/windows/vm.c
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

#include <vm/vm.h>
#include <lib/hv/minimal.h>
#include <winhvplatform.h>

struct Vm
{
    VmConfig Config;
    WHV_PARTITION_HANDLE Partition;
    PVOID Memory;
    BOOL MemoryMapped;
    UINT32 DebugLogFlags;
    HANDLE DispatcherThread;
    UINT32 DispatcherThreadCount;
};

static VmResult VmWaitDispatcherEx(Vm *Instance, BOOL Cancel);
static VOID VmCancelDispatcher(Vm *Instance);
static DWORD WINAPI VmDispatcherThread(PVOID Instance0);
static VmResult VmDispatcherUnknown(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext);
static VmResult VmDispatcherMemoryAccess(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext);
static VmResult VmDispatcherX64IoPortAccess(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext);
static VmResult VmDispatcherCanceled(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext);
static VOID VmDebugLog(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext, VmResult Result);

VmResult VmCreate(const VmConfig *Config, Vm **PInstance)
{
    VmResult Result;
    Vm *Instance = 0;
    WHV_PARTITION_PROPERTY Property = { 0 };
    WHV_CAPABILITY Capability;
    HRESULT HResult;

    *PInstance = 0;

    HResult = WHvGetCapability(
        WHvCapabilityCodeHypervisorPresent, &Capability, sizeof Capability, 0);
    if (FAILED(HResult) || !Capability.HypervisorPresent)
    {
        Result = VmMakeResult(VmErrorHypervisor, HResult);
        goto exit;
    }

    Instance = malloc(sizeof *Instance);
    if (0 == Instance)
    {
        Result = VmErrorMemory;
        goto exit;
    }

    memset(Instance, 0, sizeof *Instance);
    Instance->Config = *Config;

    if (0 == Instance->Config.CpuCount)
    {
        DWORD_PTR ProcessMask, SystemMask;

        if (!GetProcessAffinityMask(GetCurrentProcess(), &ProcessMask, &SystemMask))
        {
            Result = VmMakeResult(VmErrorInstance, GetLastError());
            goto exit;
        }

        for (Instance->Config.CpuCount = 0; 0 != ProcessMask; ProcessMask >>= 1)
            Instance->Config.CpuCount += ProcessMask & 1;
    }
    if (0 == Instance->Config.CpuCount)
        Instance->Config.CpuCount = 1;

    HResult = WHvCreatePartition(&Instance->Partition);
    if (FAILED(HResult))
    {
        Result = VmMakeResult(VmErrorInstance, HResult);
        goto exit;
    }

    Property.ProcessorCount = (UINT32)Instance->Config.CpuCount;
    HResult = WHvSetPartitionProperty(Instance->Partition,
        WHvPartitionPropertyCodeProcessorCount, &Property, sizeof Property);
    if (FAILED(HResult))
    {
        Result = VmMakeResult(VmErrorInstance, HResult);
        goto exit;
    }

    HResult = WHvSetupPartition(Instance->Partition);
    if (FAILED(HResult))
    {
        Result = VmMakeResult(VmErrorInstance, HResult);
        goto exit;
    }

    Instance->Memory = VirtualAlloc(
        0, Instance->Config.MemorySize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (0 == Instance->Memory)
    {
        Result = VmMakeResult(VmErrorInstance, GetLastError());
        goto exit;
    }

    HResult = WHvMapGpaRange(Instance->Partition,
        Instance->Memory, 0, Instance->Config.MemorySize,
        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute);
    if (FAILED(HResult))
    {
        Result = VmMakeResult(VmErrorMemory, HResult);
        goto exit;
    }
    Instance->MemoryMapped = TRUE;

    *PInstance = Instance;
    Result = VmResultSuccess;

exit:
    if (VmResultSuccess != Result && 0 != Instance)
        VmDelete(Instance);

    return Result;
}

VmResult VmDelete(Vm *Instance)
{
    if (0 != Instance->DispatcherThread)
        CloseHandle(Instance->DispatcherThread);

    if (Instance->MemoryMapped)
        WHvUnmapGpaRange(Instance->Partition, 0, Instance->Config.MemorySize);

    if (0 != Instance->Memory)
        VirtualFree(Instance->Memory, Instance->Config.MemorySize, MEM_RELEASE);

    if (0 != Instance->Partition)
        WHvDeletePartition(Instance->Partition);

    free(Instance);

    return VmResultSuccess;
}

VmResult VmSetDebugLog(Vm *Instance, unsigned Flags)
{
    Instance->DebugLogFlags = Flags;

    return VmResultSuccess;
}

VmResult VmStartDispatcher(Vm *Instance)
{
    VmResult Result;

    if (0 != Instance->DispatcherThread)
    {
        Result = VmErrorInvalid;
        goto exit;
    }

    Instance->DispatcherThreadCount = (UINT32)Instance->Config.CpuCount;
    Instance->DispatcherThread = CreateThread(0, 0, VmDispatcherThread, Instance, 0, 0);
    if (0 == Instance->DispatcherThread)
    {
        Result = VmMakeResult(VmErrorThread, GetLastError());
        goto exit;
    }

    Result = VmResultSuccess;

exit:
    return Result;
}

VmResult VmWaitDispatcher(Vm *Instance)
{
    return VmWaitDispatcherEx(Instance, FALSE);
}

VmResult VmStopDispatcher(Vm *Instance)
{
    return VmWaitDispatcherEx(Instance, TRUE);
}

static VmResult VmWaitDispatcherEx(Vm *Instance, BOOL Cancel)
{
    VmResult Result;

    if (0 == Instance->DispatcherThread)
    {
        Result = VmErrorInvalid;
        goto exit;
    }

    if (Cancel)
        VmCancelDispatcher(Instance);

    WaitForSingleObject(Instance->DispatcherThread, INFINITE);

    Result = VmResultSuccess;

exit:
    return Result;
}

static VOID VmCancelDispatcher(Vm *Instance)
{
    for (UINT32 CpuIndex = (UINT32)Instance->Config.CpuCount - 1;
        Instance->Config.CpuCount > CpuIndex; CpuIndex--)
        WHvCancelRunVirtualProcessor(Instance->Partition, CpuIndex, 0);
}

static DWORD WINAPI VmDispatcherThread(PVOID Instance0)
{
    VmResult Result;
    Vm *Instance = Instance0;
    HANDLE DispatcherThread = 0;
    UINT32 CpuIndex;
    BOOL CpuCreated = FALSE;
    WHV_RUN_VP_EXIT_CONTEXT ExitContext;
    HRESULT HResult;

    /*
     * The following code block is thread-safe because the CreateThread call
     * ensures that we run in a lockstep fashion. This is because the call
     * must act as a barrier: by the time the new thread is created it must
     * observe the world as if all previous code has run.
     */
    CpuIndex = (UINT32)Instance->Config.CpuCount - Instance->DispatcherThreadCount;
    if (1 < Instance->DispatcherThreadCount)
    {
        Instance->DispatcherThreadCount--;
        DispatcherThread = CreateThread(0, 0, VmDispatcherThread, Instance, 0, 0);
        if (0 == DispatcherThread)
        {
            Result = VmMakeResult(VmErrorThread, GetLastError());
            goto exit;
        }
    }

    HResult = WHvCreateVirtualProcessor(Instance->Partition, CpuIndex, 0);
    if (FAILED(HResult))
    {
        Result = VmMakeResult(VmErrorCpu, HResult);
        goto exit;
    }
    CpuCreated = TRUE;

    for (;;)
    {
        HResult = WHvRunVirtualProcessor(Instance->Partition,
            CpuIndex, &ExitContext, sizeof ExitContext);
        if (FAILED(HResult))
        {
            Result = VmMakeResult(VmErrorCpu, HResult);
            goto exit;
        }

        /*
         * In order to avoid a big switch statement we use a dispatch table.
         * So we squash the ExitReason into an index to the table.
         *
         * Is this really worth it? Don't know, but I did it anyway.
         * A sensible person would have done some perf measurements first.
         */
#define SQUASH(x)                       ((((x) & 0x3000) >> 8) | ((x) & 0xf))
        static VmResult (*Dispatch[64])(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext) =
        {
            [0x00] = VmDispatcherUnknown,
            [0x01] = VmDispatcherUnknown,
            [0x02] = VmDispatcherUnknown,
            [0x03] = VmDispatcherUnknown,
            [0x04] = VmDispatcherUnknown,
            [0x05] = VmDispatcherUnknown,
            [0x06] = VmDispatcherUnknown,
            [0x07] = VmDispatcherUnknown,
            [0x08] = VmDispatcherUnknown,
            [0x09] = VmDispatcherUnknown,
            [0x0a] = VmDispatcherUnknown,
            [0x0b] = VmDispatcherUnknown,
            [0x0c] = VmDispatcherUnknown,
            [0x0d] = VmDispatcherUnknown,
            [0x0e] = VmDispatcherUnknown,
            [0x0f] = VmDispatcherUnknown,
            [0x10] = VmDispatcherUnknown,
            [0x11] = VmDispatcherUnknown,
            [0x12] = VmDispatcherUnknown,
            [0x13] = VmDispatcherUnknown,
            [0x14] = VmDispatcherUnknown,
            [0x15] = VmDispatcherUnknown,
            [0x16] = VmDispatcherUnknown,
            [0x17] = VmDispatcherUnknown,
            [0x18] = VmDispatcherUnknown,
            [0x19] = VmDispatcherUnknown,
            [0x1a] = VmDispatcherUnknown,
            [0x1b] = VmDispatcherUnknown,
            [0x1c] = VmDispatcherUnknown,
            [0x1d] = VmDispatcherUnknown,
            [0x1e] = VmDispatcherUnknown,
            [0x1f] = VmDispatcherUnknown,
            [0x20] = VmDispatcherUnknown,
            [0x21] = VmDispatcherUnknown,
            [0x22] = VmDispatcherUnknown,
            [0x23] = VmDispatcherUnknown,
            [0x24] = VmDispatcherUnknown,
            [0x25] = VmDispatcherUnknown,
            [0x26] = VmDispatcherUnknown,
            [0x27] = VmDispatcherUnknown,
            [0x28] = VmDispatcherUnknown,
            [0x29] = VmDispatcherUnknown,
            [0x2a] = VmDispatcherUnknown,
            [0x2b] = VmDispatcherUnknown,
            [0x2c] = VmDispatcherUnknown,
            [0x2d] = VmDispatcherUnknown,
            [0x2e] = VmDispatcherUnknown,
            [0x2f] = VmDispatcherUnknown,
            [0x30] = VmDispatcherUnknown,
            [0x31] = VmDispatcherUnknown,
            [0x32] = VmDispatcherUnknown,
            [0x33] = VmDispatcherUnknown,
            [0x34] = VmDispatcherUnknown,
            [0x35] = VmDispatcherUnknown,
            [0x36] = VmDispatcherUnknown,
            [0x37] = VmDispatcherUnknown,
            [0x38] = VmDispatcherUnknown,
            [0x39] = VmDispatcherUnknown,
            [0x3a] = VmDispatcherUnknown,
            [0x3b] = VmDispatcherUnknown,
            [0x3c] = VmDispatcherUnknown,
            [0x3d] = VmDispatcherUnknown,
            [0x3e] = VmDispatcherUnknown,
            [0x3f] = VmDispatcherUnknown,

            [SQUASH(WHvRunVpExitReasonMemoryAccess)] = VmDispatcherMemoryAccess,
            [SQUASH(WHvRunVpExitReasonX64IoPortAccess)] = VmDispatcherX64IoPortAccess,
            [SQUASH(WHvRunVpExitReasonCanceled)] = VmDispatcherCanceled,
        };
        int Index = SQUASH(ExitContext.ExitReason);
#undef SQUASH

        Result = Dispatch[Index](Instance, &ExitContext);
        if (Instance->DebugLogFlags)
            VmDebugLog(Instance, &ExitContext, Result);
        if (VmResultSuccess != Result)
            goto exit;
    }

exit:
    VmCancelDispatcher(Instance);

    if (CpuCreated)
        WHvDeleteVirtualProcessor(Instance->Partition, CpuIndex);

    if (0 != DispatcherThread)
    {
        WaitForSingleObject(DispatcherThread, INFINITE);
        CloseHandle(DispatcherThread);
    }

    return (DWORD)Result;
}

static VmResult VmDispatcherUnknown(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    return VmErrorStop;
}

static VmResult VmDispatcherMemoryAccess(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    return VmErrorStop;
}

static VmResult VmDispatcherX64IoPortAccess(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    return VmErrorStop;
}

static VmResult VmDispatcherCanceled(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    return VmErrorStop;
}

static VOID VmDebugLog(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext, VmResult Result)
{
    char Buffer[1024];
    char *ExitReasonStr;
    DWORD Bytes;

    switch (ExitContext->ExitReason)
    {
    case WHvRunVpExitReasonNone:
        ExitReasonStr = "None";
        break;
    case WHvRunVpExitReasonMemoryAccess:
        ExitReasonStr = "MemoryAccess";
        break;
    case WHvRunVpExitReasonX64IoPortAccess:
        ExitReasonStr = "X64IoPortAccess";
        break;
    case WHvRunVpExitReasonUnrecoverableException:
        ExitReasonStr = "UnrecoverableException";
        break;
    case WHvRunVpExitReasonInvalidVpRegisterValue:
        ExitReasonStr = "InvalidVpRegisterValue";
        break;
    case WHvRunVpExitReasonUnsupportedFeature:
        ExitReasonStr = "UnsupportedFeature";
        break;
    case WHvRunVpExitReasonX64InterruptWindow:
        ExitReasonStr = "X64InterruptWindow";
        break;
    case WHvRunVpExitReasonX64Halt:
        ExitReasonStr = "X64Halt";
        break;
    case WHvRunVpExitReasonX64ApicEoi:
        ExitReasonStr = "X64ApicEoi";
        break;
    case WHvRunVpExitReasonX64MsrAccess:
        ExitReasonStr = "X64MsrAccess";
        break;
    case WHvRunVpExitReasonX64Cpuid:
        ExitReasonStr = "X64Cpuid";
        break;
    case WHvRunVpExitReasonException:
        ExitReasonStr = "Exception";
        break;
    case WHvRunVpExitReasonX64Rdtsc:
        ExitReasonStr = "X64Rdtsc";
        break;
    case WHvRunVpExitReasonX64ApicSmiTrap:
        ExitReasonStr = "X64ApicSmiTrap";
        break;
    case WHvRunVpExitReasonHypercall:
        ExitReasonStr = "Hypercall";
        break;
    case WHvRunVpExitReasonX64ApicInitSipiTrap:
        ExitReasonStr = "X64ApicInitSipiTrap";
        break;
    case WHvRunVpExitReasonX64ApicWriteTrap:
        ExitReasonStr = "X64ApicWriteTrap";
        break;
    case WHvRunVpExitReasonCanceled:
        ExitReasonStr = "Canceled";
        break;
    }

    wsprintfA(Buffer, "%s(cs:rip=%04x:%p, efl=%08x, pe=%d) = %d\n",
        ExitReasonStr,
        ExitContext->VpContext.Cs.Selector, ExitContext->VpContext.Rip,
        (UINT32)ExitContext->VpContext.Rflags,
        ExitContext->VpContext.ExecutionState.Cr0Pe,
        VmGetError(Result));
    Buffer[sizeof Buffer - 1] = '\0';
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), Buffer, lstrlenA(Buffer), &Bytes, 0);
}
