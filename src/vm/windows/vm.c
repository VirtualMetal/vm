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

static DWORD WINAPI VmDispatcherThread(PVOID Instance0);
static VOID VmCancelDispatch(Vm *Instance);
static VmResult VmDispatchUnknown(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext);
static VmResult VmDispatchMemoryAccess(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext);
static VmResult VmDispatchX64IoPortAccess(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext);
static VmResult VmDispatchCanceled(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext);
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
        Result = VmMakeResult(HResult, VmErrorHypervisor);
        goto exit;
    }

    Instance = malloc(sizeof *Instance);
    if (0 == Instance)
    {
        Result = VmMakeResult(ERROR_OUTOFMEMORY, VmErrorMemory);
        goto exit;
    }

    memset(Instance, 0, sizeof *Instance);
    Instance->Config = *Config;

    if (0 == Instance->Config.CpuCount)
    {
        DWORD_PTR ProcessMask, SystemMask;

        if (!GetProcessAffinityMask(GetCurrentProcess(), &ProcessMask, &SystemMask))
        {
            Result = VmMakeResult(GetLastError(), VmErrorInstance);
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
        Result = VmMakeResult(HResult, VmErrorInstance);
        goto exit;
    }

    Property.ProcessorCount = (UINT32)Instance->Config.CpuCount;
    HResult = WHvSetPartitionProperty(Instance->Partition,
        WHvPartitionPropertyCodeProcessorCount, &Property, sizeof Property);
    if (FAILED(HResult))
    {
        Result = VmMakeResult(HResult, VmErrorInstance);
        goto exit;
    }

    HResult = WHvSetupPartition(Instance->Partition);
    if (FAILED(HResult))
    {
        Result = VmMakeResult(HResult, VmErrorInstance);
        goto exit;
    }

    Instance->Memory = VirtualAlloc(
        0, Instance->Config.MemorySize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (0 == Instance->Memory)
    {
        Result = VmMakeResult(GetLastError(), VmErrorInstance);
        goto exit;
    }

    HResult = WHvMapGpaRange(Instance->Partition,
        Instance->Memory, 0, Instance->Config.MemorySize,
        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute);
    if (FAILED(HResult))
    {
        Result = VmMakeResult(HResult, VmErrorMemory);
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
        Result = VmMakeResult(0, VmErrorInvalid);
        goto exit;
    }

    Instance->DispatcherThreadCount = (UINT32)Instance->Config.CpuCount;
    Instance->DispatcherThread = CreateThread(0, 0, VmDispatcherThread, Instance, 0, 0);
    if (0 == Instance->DispatcherThread)
    {
        Result = VmMakeResult(GetLastError(), VmErrorThread);
        goto exit;
    }

    Result = VmResultSuccess;

exit:
    return Result;
}

VmResult VmStopDispatcher(Vm *Instance)
{
    VmResult Result;

    if (0 == Instance->DispatcherThread)
    {
        Result = VmMakeResult(0, VmErrorInvalid);
        goto exit;
    }

    VmCancelDispatch(Instance);

    WaitForSingleObject(Instance->DispatcherThread, INFINITE);
    CloseHandle(Instance->DispatcherThread);
    Instance->DispatcherThread = 0;

    Result = VmResultSuccess;

exit:
    return Result;
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
            Result = VmMakeResult(GetLastError(), VmErrorThread);
            goto exit;
        }
    }

    HResult = WHvCreateVirtualProcessor(Instance->Partition, CpuIndex, 0);
    if (FAILED(HResult))
    {
        Result = VmMakeResult(HResult, VmErrorCpu);
        goto exit;
    }
    CpuCreated = TRUE;

    for (;;)
    {
        HResult = WHvRunVirtualProcessor(Instance->Partition,
            CpuIndex, &ExitContext, sizeof ExitContext);
        if (FAILED(HResult))
        {
            Result = VmMakeResult(HResult, VmErrorCpu);
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
            [0x00] = VmDispatchUnknown,
            [0x01] = VmDispatchUnknown,
            [0x02] = VmDispatchUnknown,
            [0x03] = VmDispatchUnknown,
            [0x04] = VmDispatchUnknown,
            [0x05] = VmDispatchUnknown,
            [0x06] = VmDispatchUnknown,
            [0x07] = VmDispatchUnknown,
            [0x08] = VmDispatchUnknown,
            [0x09] = VmDispatchUnknown,
            [0x0a] = VmDispatchUnknown,
            [0x0b] = VmDispatchUnknown,
            [0x0c] = VmDispatchUnknown,
            [0x0d] = VmDispatchUnknown,
            [0x0e] = VmDispatchUnknown,
            [0x0f] = VmDispatchUnknown,
            [0x10] = VmDispatchUnknown,
            [0x11] = VmDispatchUnknown,
            [0x12] = VmDispatchUnknown,
            [0x13] = VmDispatchUnknown,
            [0x14] = VmDispatchUnknown,
            [0x15] = VmDispatchUnknown,
            [0x16] = VmDispatchUnknown,
            [0x17] = VmDispatchUnknown,
            [0x18] = VmDispatchUnknown,
            [0x19] = VmDispatchUnknown,
            [0x1a] = VmDispatchUnknown,
            [0x1b] = VmDispatchUnknown,
            [0x1c] = VmDispatchUnknown,
            [0x1d] = VmDispatchUnknown,
            [0x1e] = VmDispatchUnknown,
            [0x1f] = VmDispatchUnknown,
            [0x20] = VmDispatchUnknown,
            [0x21] = VmDispatchUnknown,
            [0x22] = VmDispatchUnknown,
            [0x23] = VmDispatchUnknown,
            [0x24] = VmDispatchUnknown,
            [0x25] = VmDispatchUnknown,
            [0x26] = VmDispatchUnknown,
            [0x27] = VmDispatchUnknown,
            [0x28] = VmDispatchUnknown,
            [0x29] = VmDispatchUnknown,
            [0x2a] = VmDispatchUnknown,
            [0x2b] = VmDispatchUnknown,
            [0x2c] = VmDispatchUnknown,
            [0x2d] = VmDispatchUnknown,
            [0x2e] = VmDispatchUnknown,
            [0x2f] = VmDispatchUnknown,
            [0x30] = VmDispatchUnknown,
            [0x31] = VmDispatchUnknown,
            [0x32] = VmDispatchUnknown,
            [0x33] = VmDispatchUnknown,
            [0x34] = VmDispatchUnknown,
            [0x35] = VmDispatchUnknown,
            [0x36] = VmDispatchUnknown,
            [0x37] = VmDispatchUnknown,
            [0x38] = VmDispatchUnknown,
            [0x39] = VmDispatchUnknown,
            [0x3a] = VmDispatchUnknown,
            [0x3b] = VmDispatchUnknown,
            [0x3c] = VmDispatchUnknown,
            [0x3d] = VmDispatchUnknown,
            [0x3e] = VmDispatchUnknown,
            [0x3f] = VmDispatchUnknown,

            [SQUASH(WHvRunVpExitReasonMemoryAccess)] = VmDispatchMemoryAccess,
            [SQUASH(WHvRunVpExitReasonX64IoPortAccess)] = VmDispatchX64IoPortAccess,
            [SQUASH(WHvRunVpExitReasonCanceled)] = VmDispatchCanceled,
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
    VmCancelDispatch(Instance);

    if (CpuCreated)
        WHvDeleteVirtualProcessor(Instance->Partition, CpuIndex);

    if (0 != DispatcherThread)
    {
        WaitForSingleObject(DispatcherThread, INFINITE);
        CloseHandle(DispatcherThread);
    }

    return (DWORD)Result;
}

static VOID VmCancelDispatch(Vm *Instance)
{
    for (UINT32 CpuIndex = (UINT32)Instance->Config.CpuCount - 1;
        Instance->Config.CpuCount > CpuIndex; CpuIndex--)
        WHvCancelRunVirtualProcessor(Instance->Partition, CpuIndex, 0);
}

static VmResult VmDispatchUnknown(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    return VmErrorStop;
}

static VmResult VmDispatchMemoryAccess(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    return VmResultSuccess;
}

static VmResult VmDispatchX64IoPortAccess(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    return VmResultSuccess;
}

static VmResult VmDispatchCanceled(Vm *Instance, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
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
