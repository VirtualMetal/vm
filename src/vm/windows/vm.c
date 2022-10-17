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
#include <vm/internal.h>
#include <winhvplatform.h>

struct vm
{
    vm_config_t config;
    WHV_PARTITION_HANDLE partition;
    PVOID memory;
    BOOL memory_mapped;
    UINT32 debug_log_flags;
    HANDLE dispatcher_thread;
    UINT32 dispatcher_thread_count;
};

static vm_result_t vm_wait_dispatcher_ex(vm_t *instance, BOOL cancel);
static VOID vm_cancel_dispatcher(vm_t *instance);
static DWORD WINAPI vm_dispatcher_thread(PVOID instance0);
static vm_result_t vm_dispatcher_unknown(vm_t *instance, WHV_RUN_VP_EXIT_CONTEXT *exit_context);
static vm_result_t vm_dispatcher_MemoryAccess(vm_t *instance, WHV_RUN_VP_EXIT_CONTEXT *exit_context);
static vm_result_t vm_dispatcher_X64IoPortAccess(vm_t *instance, WHV_RUN_VP_EXIT_CONTEXT *exit_context);
static vm_result_t vm_dispatcher_Canceled(vm_t *instance, WHV_RUN_VP_EXIT_CONTEXT *exit_context);
static VOID vm_debug_log(UINT32 cpu_index, WHV_RUN_VP_EXIT_CONTEXT *exit_context, vm_result_t result);

vm_result_t vm_create(const vm_config_t *config, vm_t **pinstance)
{
    vm_result_t result;
    vm_t *instance = 0;
    WHV_PARTITION_PROPERTY property = { 0 };
    WHV_CAPABILITY capability;
    HRESULT hresult;

    *pinstance = 0;

    hresult = WHvGetCapability(
        WHvCapabilityCodeHypervisorPresent, &capability, sizeof capability, 0);
    if (FAILED(hresult) || !capability.HypervisorPresent)
    {
        result = vm_make_result(VM_ERROR_HYPERVISOR, hresult);
        goto exit;
    }

    instance = malloc(sizeof *instance);
    if (0 == instance)
    {
        result = VM_ERROR_MEMORY;
        goto exit;
    }

    memset(instance, 0, sizeof *instance);
    instance->config = *config;

    if (0 == instance->config.cpu_count)
    {
        DWORD_PTR process_mask, system_mask;
        if (!GetProcessAffinityMask(GetCurrentProcess(), &process_mask, &system_mask))
        {
            result = vm_make_result(VM_ERROR_INSTANCE, GetLastError());
            goto exit;
        }
        for (instance->config.cpu_count = 0; 0 != process_mask; process_mask >>= 1)
            instance->config.cpu_count += process_mask & 1;
    }
    if (0 == instance->config.cpu_count)
        instance->config.cpu_count = 1;

    hresult = WHvCreatePartition(&instance->partition);
    if (FAILED(hresult))
    {
        result = vm_make_result(VM_ERROR_INSTANCE, hresult);
        goto exit;
    }

    property.ProcessorCount = (UINT32)instance->config.cpu_count;
    hresult = WHvSetPartitionProperty(instance->partition,
        WHvPartitionPropertyCodeProcessorCount, &property, sizeof property);
    if (FAILED(hresult))
    {
        result = vm_make_result(VM_ERROR_INSTANCE, hresult);
        goto exit;
    }

    hresult = WHvSetupPartition(instance->partition);
    if (FAILED(hresult))
    {
        result = vm_make_result(VM_ERROR_INSTANCE, hresult);
        goto exit;
    }

    instance->memory = VirtualAlloc(
        0, instance->config.memory_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (0 == instance->memory)
    {
        result = vm_make_result(VM_ERROR_MEMORY, GetLastError());
        goto exit;
    }

    hresult = WHvMapGpaRange(instance->partition,
        instance->memory, 0, instance->config.memory_size,
        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute);
    if (FAILED(hresult))
    {
        result = vm_make_result(VM_ERROR_INSTANCE, hresult);
        goto exit;
    }
    instance->memory_mapped = TRUE;

    *pinstance = instance;
    result = VM_RESULT_SUCCESS;

exit:
    if (VM_RESULT_SUCCESS != result && 0 != instance)
        vm_delete(instance);

    return result;
}

vm_result_t vm_delete(vm_t *instance)
{
    if (0 != instance->dispatcher_thread)
        CloseHandle(instance->dispatcher_thread);

    if (instance->memory_mapped)
        WHvUnmapGpaRange(instance->partition, 0, instance->config.memory_size);

    if (0 != instance->memory)
        VirtualFree(instance->memory, instance->config.memory_size, MEM_RELEASE);

    if (0 != instance->partition)
        WHvDeletePartition(instance->partition);

    free(instance);

    return VM_RESULT_SUCCESS;
}

vm_result_t vm_set_debug_log(vm_t *instance, unsigned flags)
{
    instance->debug_log_flags = flags;

    return VM_RESULT_SUCCESS;
}

vm_result_t vm_start_dispatcher(vm_t *instance)
{
    vm_result_t result;

    if (0 != instance->dispatcher_thread)
    {
        result = VM_ERROR_MISUSE;
        goto exit;
    }

    instance->dispatcher_thread_count = (UINT32)instance->config.cpu_count;
    instance->dispatcher_thread = CreateThread(0, 0, vm_dispatcher_thread, instance, 0, 0);
    if (0 == instance->dispatcher_thread)
    {
        result = vm_make_result(VM_ERROR_THREAD, GetLastError());
        goto exit;
    }

    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

vm_result_t vm_wait_dispatcher(vm_t *instance)
{
    return vm_wait_dispatcher_ex(instance, FALSE);
}

vm_result_t vm_stop_dispatcher(vm_t *instance)
{
    return vm_wait_dispatcher_ex(instance, TRUE);
}

static vm_result_t vm_wait_dispatcher_ex(vm_t *instance, BOOL cancel)
{
    vm_result_t result;

    if (0 == instance->dispatcher_thread)
    {
        result = VM_ERROR_MISUSE;
        goto exit;
    }

    if (cancel)
        vm_cancel_dispatcher(instance);

    WaitForSingleObject(instance->dispatcher_thread, INFINITE);

    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

static VOID vm_cancel_dispatcher(vm_t *instance)
{
    for (UINT32 cpu_index = (UINT32)instance->config.cpu_count - 1;
        instance->config.cpu_count > cpu_index; cpu_index--)
        WHvCancelRunVirtualProcessor(instance->partition, cpu_index, 0);
}

static DWORD WINAPI vm_dispatcher_thread(PVOID instance0)
{
    vm_result_t result;
    vm_t *instance = instance0;
    HANDLE dispatcher_thread = 0;
    UINT32 cpu_index;
    BOOL cpu_created = FALSE;
    WHV_RUN_VP_EXIT_CONTEXT exit_context;
    HRESULT hresult;

    /*
     * The following code block is thread-safe because the CreateThread call
     * ensures that we run in a lockstep fashion. This is because the call
     * must act as a barrier: by the time the new thread is created it must
     * observe the world as if all previous code has run.
     */
    cpu_index = (UINT32)instance->config.cpu_count - instance->dispatcher_thread_count;
    if (1 < instance->dispatcher_thread_count)
    {
        instance->dispatcher_thread_count--;
        dispatcher_thread = CreateThread(0, 0, vm_dispatcher_thread, instance, 0, 0);
        if (0 == dispatcher_thread)
        {
            result = vm_make_result(VM_ERROR_THREAD, GetLastError());
            goto exit;
        }
    }

    hresult = WHvCreateVirtualProcessor(instance->partition, cpu_index, 0);
    if (FAILED(hresult))
    {
        result = vm_make_result(VM_ERROR_CPU, hresult);
        goto exit;
    }
    cpu_created = TRUE;

    for (;;)
    {
        hresult = WHvRunVirtualProcessor(instance->partition,
            cpu_index, &exit_context, sizeof exit_context);
        if (FAILED(hresult))
        {
            result = vm_make_result(VM_ERROR_CPU, hresult);
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
        static vm_result_t (*dispatch[64])(vm_t *instance, WHV_RUN_VP_EXIT_CONTEXT *exit_context) =
        {
            [0x00] = vm_dispatcher_unknown,
            [0x01] = vm_dispatcher_unknown,
            [0x02] = vm_dispatcher_unknown,
            [0x03] = vm_dispatcher_unknown,
            [0x04] = vm_dispatcher_unknown,
            [0x05] = vm_dispatcher_unknown,
            [0x06] = vm_dispatcher_unknown,
            [0x07] = vm_dispatcher_unknown,
            [0x08] = vm_dispatcher_unknown,
            [0x09] = vm_dispatcher_unknown,
            [0x0a] = vm_dispatcher_unknown,
            [0x0b] = vm_dispatcher_unknown,
            [0x0c] = vm_dispatcher_unknown,
            [0x0d] = vm_dispatcher_unknown,
            [0x0e] = vm_dispatcher_unknown,
            [0x0f] = vm_dispatcher_unknown,
            [0x10] = vm_dispatcher_unknown,
            [0x11] = vm_dispatcher_unknown,
            [0x12] = vm_dispatcher_unknown,
            [0x13] = vm_dispatcher_unknown,
            [0x14] = vm_dispatcher_unknown,
            [0x15] = vm_dispatcher_unknown,
            [0x16] = vm_dispatcher_unknown,
            [0x17] = vm_dispatcher_unknown,
            [0x18] = vm_dispatcher_unknown,
            [0x19] = vm_dispatcher_unknown,
            [0x1a] = vm_dispatcher_unknown,
            [0x1b] = vm_dispatcher_unknown,
            [0x1c] = vm_dispatcher_unknown,
            [0x1d] = vm_dispatcher_unknown,
            [0x1e] = vm_dispatcher_unknown,
            [0x1f] = vm_dispatcher_unknown,
            [0x20] = vm_dispatcher_unknown,
            [0x21] = vm_dispatcher_unknown,
            [0x22] = vm_dispatcher_unknown,
            [0x23] = vm_dispatcher_unknown,
            [0x24] = vm_dispatcher_unknown,
            [0x25] = vm_dispatcher_unknown,
            [0x26] = vm_dispatcher_unknown,
            [0x27] = vm_dispatcher_unknown,
            [0x28] = vm_dispatcher_unknown,
            [0x29] = vm_dispatcher_unknown,
            [0x2a] = vm_dispatcher_unknown,
            [0x2b] = vm_dispatcher_unknown,
            [0x2c] = vm_dispatcher_unknown,
            [0x2d] = vm_dispatcher_unknown,
            [0x2e] = vm_dispatcher_unknown,
            [0x2f] = vm_dispatcher_unknown,
            [0x30] = vm_dispatcher_unknown,
            [0x31] = vm_dispatcher_unknown,
            [0x32] = vm_dispatcher_unknown,
            [0x33] = vm_dispatcher_unknown,
            [0x34] = vm_dispatcher_unknown,
            [0x35] = vm_dispatcher_unknown,
            [0x36] = vm_dispatcher_unknown,
            [0x37] = vm_dispatcher_unknown,
            [0x38] = vm_dispatcher_unknown,
            [0x39] = vm_dispatcher_unknown,
            [0x3a] = vm_dispatcher_unknown,
            [0x3b] = vm_dispatcher_unknown,
            [0x3c] = vm_dispatcher_unknown,
            [0x3d] = vm_dispatcher_unknown,
            [0x3e] = vm_dispatcher_unknown,
            [0x3f] = vm_dispatcher_unknown,

            [SQUASH(WHvRunVpExitReasonMemoryAccess)] = vm_dispatcher_MemoryAccess,
            [SQUASH(WHvRunVpExitReasonX64IoPortAccess)] = vm_dispatcher_X64IoPortAccess,
            [SQUASH(WHvRunVpExitReasonCanceled)] = vm_dispatcher_Canceled,
        };
        int index = SQUASH(exit_context.ExitReason);
#undef SQUASH

        result = dispatch[index](instance, &exit_context);
        if (instance->debug_log_flags)
            vm_debug_log(cpu_index, &exit_context, result);
        if (VM_RESULT_SUCCESS != result)
            goto exit;
    }

exit:
    vm_cancel_dispatcher(instance);

    if (cpu_created)
        WHvDeleteVirtualProcessor(instance->partition, cpu_index);

    if (0 != dispatcher_thread)
    {
        WaitForSingleObject(dispatcher_thread, INFINITE);
        CloseHandle(dispatcher_thread);
    }

    return (DWORD)result;
}

static vm_result_t vm_dispatcher_unknown(vm_t *instance, WHV_RUN_VP_EXIT_CONTEXT *exit_context)
{
    return VM_ERROR_STOP;
}

static vm_result_t vm_dispatcher_MemoryAccess(vm_t *instance, WHV_RUN_VP_EXIT_CONTEXT *exit_context)
{
    return VM_ERROR_STOP;
}

static vm_result_t vm_dispatcher_X64IoPortAccess(vm_t *instance, WHV_RUN_VP_EXIT_CONTEXT *exit_context)
{
    return VM_ERROR_STOP;
}

static vm_result_t vm_dispatcher_Canceled(vm_t *instance, WHV_RUN_VP_EXIT_CONTEXT *exit_context)
{
    return VM_ERROR_STOP;
}

static VOID vm_debug_log(UINT32 cpu_index, WHV_RUN_VP_EXIT_CONTEXT *exit_context, vm_result_t result)
{
    char buffer[1024];
    char *exit_reason_str;
    DWORD bytes;

    switch (exit_context->ExitReason)
    {
    case WHvRunVpExitReasonNone:
        exit_reason_str = "None";
        break;
    case WHvRunVpExitReasonMemoryAccess:
        exit_reason_str = "MemoryAccess";
        break;
    case WHvRunVpExitReasonX64IoPortAccess:
        exit_reason_str = "X64IoPortAccess";
        break;
    case WHvRunVpExitReasonUnrecoverableException:
        exit_reason_str = "UnrecoverableException";
        break;
    case WHvRunVpExitReasonInvalidVpRegisterValue:
        exit_reason_str = "InvalidVpRegisterValue";
        break;
    case WHvRunVpExitReasonUnsupportedFeature:
        exit_reason_str = "UnsupportedFeature";
        break;
    case WHvRunVpExitReasonX64InterruptWindow:
        exit_reason_str = "X64InterruptWindow";
        break;
    case WHvRunVpExitReasonX64Halt:
        exit_reason_str = "X64Halt";
        break;
    case WHvRunVpExitReasonX64ApicEoi:
        exit_reason_str = "X64ApicEoi";
        break;
    case WHvRunVpExitReasonX64MsrAccess:
        exit_reason_str = "X64MsrAccess";
        break;
    case WHvRunVpExitReasonX64Cpuid:
        exit_reason_str = "X64Cpuid";
        break;
    case WHvRunVpExitReasonException:
        exit_reason_str = "Exception";
        break;
    case WHvRunVpExitReasonX64Rdtsc:
        exit_reason_str = "X64Rdtsc";
        break;
    case WHvRunVpExitReasonX64ApicSmiTrap:
        exit_reason_str = "X64ApicSmiTrap";
        break;
    case WHvRunVpExitReasonHypercall:
        exit_reason_str = "Hypercall";
        break;
    case WHvRunVpExitReasonX64ApicInitSipiTrap:
        exit_reason_str = "X64ApicInitSipiTrap";
        break;
    case WHvRunVpExitReasonX64ApicWriteTrap:
        exit_reason_str = "X64ApicWriteTrap";
        break;
    case WHvRunVpExitReasonCanceled:
        exit_reason_str = "Canceled";
        break;
    }

    wsprintfA(buffer, "[%u] %s(cs:rip=%04x:%p, efl=%08x, pe=%d) = %d\n",
        (unsigned)cpu_index,
        exit_reason_str,
        exit_context->VpContext.Cs.Selector, exit_context->VpContext.Rip,
        (UINT32)exit_context->VpContext.Rflags,
        exit_context->VpContext.ExecutionState.Cr0Pe,
        vm_result_error(result));
    buffer[sizeof buffer - 1] = '\0';
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), buffer, lstrlenA(buffer), &bytes, 0);
}
