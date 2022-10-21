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
    void *memory;
    unsigned debug_log_flags;
    SRWLOCK cancel_lock;
    HANDLE thread;                      /* protected by cancel_lock */
    vm_count_t thread_count;
    vm_result_t thread_result;
    unsigned
        is_cancelled:1,                 /* protected by cancel_lock */
        has_mapped_range:1;
};

static void vm_thread_set_cancelled(HANDLE thread);
static int vm_thread_is_cancelled(HANDLE thread);
static DWORD WINAPI vm_thread(PVOID instance0);
static vm_result_t vm_cpuexit_unknown(vm_t *instance, WHV_RUN_VP_EXIT_CONTEXT *exit_context);
static vm_result_t vm_cpuexit_MemoryAccess(vm_t *instance, WHV_RUN_VP_EXIT_CONTEXT *exit_context);
static vm_result_t vm_cpuexit_X64IoPortAccess(vm_t *instance, WHV_RUN_VP_EXIT_CONTEXT *exit_context);
static vm_result_t vm_cpuexit_Canceled(vm_t *instance, WHV_RUN_VP_EXIT_CONTEXT *exit_context);
static void vm_debug_log(UINT32 cpu_index, WHV_RUN_VP_EXIT_CONTEXT *exit_context, vm_result_t result);

vm_result_t vm_create(const vm_config_t *config, vm_t **pinstance)
{
    vm_result_t result;
    vm_t *instance = 0;
    WHV_PARTITION_PROPERTY property;
    WHV_CAPABILITY capability;
    HRESULT hresult;

    *pinstance = 0;

    hresult = WHvGetCapability(
        WHvCapabilityCodeHypervisorPresent, &capability, sizeof capability, 0);
    if (FAILED(hresult) || !capability.HypervisorPresent)
    {
        result = vm_result(VM_ERROR_HYPERVISOR, hresult);
        goto exit;
    }

    instance = malloc(sizeof *instance);
    if (0 == instance)
    {
        result = vm_result(VM_ERROR_MEMORY, 0);
        goto exit;
    }

    memset(instance, 0, sizeof *instance);
    instance->config = *config;
    InitializeSRWLock(&instance->cancel_lock);

    if (0 == instance->config.cpu_count)
    {
        DWORD_PTR process_mask, system_mask;
        if (!GetProcessAffinityMask(GetCurrentProcess(), &process_mask, &system_mask))
        {
            result = vm_result(VM_ERROR_HYPERVISOR, GetLastError());
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
        result = vm_result(VM_ERROR_HYPERVISOR, hresult);
        goto exit;
    }

    memset(&property, 0, sizeof property);
    property.ProcessorCount = (UINT32)instance->config.cpu_count;
    hresult = WHvSetPartitionProperty(instance->partition,
        WHvPartitionPropertyCodeProcessorCount, &property, sizeof property);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_HYPERVISOR, hresult);
        goto exit;
    }

    hresult = WHvSetupPartition(instance->partition);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_HYPERVISOR, hresult);
        goto exit;
    }

    instance->memory = VirtualAlloc(
        0, instance->config.memory_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (0 == instance->memory)
    {
        result = vm_result(VM_ERROR_MEMORY, GetLastError());
        goto exit;
    }

    hresult = WHvMapGpaRange(instance->partition,
        instance->memory, 0, instance->config.memory_size,
        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_HYPERVISOR, hresult);
        goto exit;
    }
    instance->has_mapped_range = 1;

    *pinstance = instance;
    result = VM_RESULT_SUCCESS;

exit:
    if (!vm_result_check(result) && 0 != instance)
        vm_delete(instance);

    return result;
}

vm_result_t vm_delete(vm_t *instance)
{
    if (instance->has_mapped_range)
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

vm_result_t vm_start(vm_t *instance)
{
    vm_result_t result;

    if (0 != instance->thread)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    InterlockedExchange64(&instance->thread_result, VM_RESULT_SUCCESS);

    AcquireSRWLockExclusive(&instance->cancel_lock);

    if (!instance->is_cancelled)
    {
        instance->thread_count = instance->config.cpu_count;
        instance->thread = CreateThread(0, 0, vm_thread, instance, 0, 0);
        if (0 == instance->thread)
            result = vm_result(VM_ERROR_VCPU, GetLastError());
    }
    else
        result = vm_result(VM_ERROR_CANCELLED, 0);

    ReleaseSRWLockExclusive(&instance->cancel_lock);

    if (0 == instance->thread)
        goto exit;

    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

vm_result_t vm_wait(vm_t *instance)
{
    vm_result_t result;

    if (0 == instance->thread)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    WaitForSingleObject(instance->thread, INFINITE);

    AcquireSRWLockExclusive(&instance->cancel_lock);

    CloseHandle(instance->thread);
    instance->thread = 0;

    ReleaseSRWLockExclusive(&instance->cancel_lock);

    result = InterlockedCompareExchange64(&instance->thread_result, 0, 0);

exit:
    return result;
}

vm_result_t vm_cancel(vm_t *instance)
{
    /*
     * Cancel CPU #0, which will end its thread and cancel CPU #1, etc.
     */

    AcquireSRWLockExclusive(&instance->cancel_lock);

    instance->is_cancelled = 1;
    if (0 != instance->thread)
    {
        vm_thread_set_cancelled(instance->thread);
        WHvCancelRunVirtualProcessor(instance->partition, 0, 0);
    }

    ReleaseSRWLockExclusive(&instance->cancel_lock);

    return VM_RESULT_SUCCESS;
}

static void vm_thread_set_cancelled(HANDLE thread)
{
    /* abuse the thread description to set the "cancelled" flag */
    SetThreadDescription(thread, L"CANCELLED");

    MemoryBarrier();
}

static int vm_thread_is_cancelled(HANDLE thread)
{
    int result;
    HRESULT hresult;
    PWSTR description;

    MemoryBarrier();

    /* abuse the thread description to get the "cancelled" flag */
    hresult = GetThreadDescription(thread, &description);
    if (FAILED(hresult))
        return 0;

    result = 0 == lstrcmpW(description, L"CANCELLED");
    LocalFree(description);
    return result;
}

static DWORD WINAPI vm_thread(PVOID instance0)
{
    /*
     * Dispatcher thread blueprint:
     *
     * - Create the virtual CPU. After the virtual CPU has been created it can be cancelled.
     *
     * - Check the thread "cancel" flag. This avoids a situation where an attempt to cancel
     * the thread's virtual CPU happens before it is created.
     *
     *     - When cancelling a thread, we first set the cancel flag and then cancel the
     *     virtual CPU. OTOH when creating a thread, we first create the virtual CPU and then
     *     check the cancel flag. This interleaving ensures that no cancellations are lost.
     *
     * - Create the next dispatcher thread.
     *
     * - Run the virtual CPU in a loop. If there is any error the loop will exit and will
     * initiate a dispatcher shutdown.
     *
     * - If there is a next thread set its cancel flag. This avoids a situation where
     * the next thread's virtual CPU has not been created yet.
     *
     * - Cancel the next virtual CPU. Usually vm_cancel will cancel the first dispatcher
     * thread, which will cancel the next one and so on. However if an error happens in
     * the virtual CPU loop of a thread that is not the first, then this thread will cancel
     * the next thread and so on until the last thread, which does not have a next thread.
     * The last thread however will cancel the first thread's virtual CPU (CPU #0), which
     * is guaranteed to exist (so vm_thread_set_cancelled is not necessary). The first thread
     * will then cancel the next thread and so on until all threads are cancelled. Notice that
     * in this process it is possible to cancel a virtual CPU that has already been deleted;
     * however this is benign.
     */

    vm_result_t result;
    vm_t *instance = instance0;
    UINT32 cpu_index;
    BOOL has_cpu = FALSE;
    HANDLE next_thread = 0;
    WHV_RUN_VP_EXIT_CONTEXT exit_context;
    HRESULT hresult;

    cpu_index = (UINT32)(instance->config.cpu_count - instance->thread_count);

    hresult = WHvCreateVirtualProcessor(instance->partition, cpu_index, 0);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_VCPU, hresult);
        goto exit;
    }
    has_cpu = TRUE;

    if (vm_thread_is_cancelled(GetCurrentThread()))
    {
        result = vm_result(VM_ERROR_CANCELLED, 0);
        goto exit;
    }

    /*
     * The following code block is thread-safe because the CreateThread call
     * ensures that we run in a lockstep fashion. This is because the call
     * must act as a barrier: by the time the new thread is created it must
     * observe the world as if all previous code has run.
     */
    if (1 < instance->thread_count)
    {
        instance->thread_count--;
        next_thread = CreateThread(0, 0, vm_thread, instance, 0, 0);
        if (0 == next_thread)
        {
            result = vm_result(VM_ERROR_VCPU, GetLastError());
            goto exit;
        }
    }

    for (;;)
    {
        hresult = WHvRunVirtualProcessor(instance->partition,
            cpu_index, &exit_context, sizeof exit_context);
        if (FAILED(hresult))
        {
            result = vm_result(VM_ERROR_VCPU, hresult);
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
            [0x00] = vm_cpuexit_unknown,
            [0x01] = vm_cpuexit_unknown,
            [0x02] = vm_cpuexit_unknown,
            [0x03] = vm_cpuexit_unknown,
            [0x04] = vm_cpuexit_unknown,
            [0x05] = vm_cpuexit_unknown,
            [0x06] = vm_cpuexit_unknown,
            [0x07] = vm_cpuexit_unknown,
            [0x08] = vm_cpuexit_unknown,
            [0x09] = vm_cpuexit_unknown,
            [0x0a] = vm_cpuexit_unknown,
            [0x0b] = vm_cpuexit_unknown,
            [0x0c] = vm_cpuexit_unknown,
            [0x0d] = vm_cpuexit_unknown,
            [0x0e] = vm_cpuexit_unknown,
            [0x0f] = vm_cpuexit_unknown,
            [0x10] = vm_cpuexit_unknown,
            [0x11] = vm_cpuexit_unknown,
            [0x12] = vm_cpuexit_unknown,
            [0x13] = vm_cpuexit_unknown,
            [0x14] = vm_cpuexit_unknown,
            [0x15] = vm_cpuexit_unknown,
            [0x16] = vm_cpuexit_unknown,
            [0x17] = vm_cpuexit_unknown,
            [0x18] = vm_cpuexit_unknown,
            [0x19] = vm_cpuexit_unknown,
            [0x1a] = vm_cpuexit_unknown,
            [0x1b] = vm_cpuexit_unknown,
            [0x1c] = vm_cpuexit_unknown,
            [0x1d] = vm_cpuexit_unknown,
            [0x1e] = vm_cpuexit_unknown,
            [0x1f] = vm_cpuexit_unknown,
            [0x20] = vm_cpuexit_unknown,
            [0x21] = vm_cpuexit_unknown,
            [0x22] = vm_cpuexit_unknown,
            [0x23] = vm_cpuexit_unknown,
            [0x24] = vm_cpuexit_unknown,
            [0x25] = vm_cpuexit_unknown,
            [0x26] = vm_cpuexit_unknown,
            [0x27] = vm_cpuexit_unknown,
            [0x28] = vm_cpuexit_unknown,
            [0x29] = vm_cpuexit_unknown,
            [0x2a] = vm_cpuexit_unknown,
            [0x2b] = vm_cpuexit_unknown,
            [0x2c] = vm_cpuexit_unknown,
            [0x2d] = vm_cpuexit_unknown,
            [0x2e] = vm_cpuexit_unknown,
            [0x2f] = vm_cpuexit_unknown,
            [0x30] = vm_cpuexit_unknown,
            [0x31] = vm_cpuexit_unknown,
            [0x32] = vm_cpuexit_unknown,
            [0x33] = vm_cpuexit_unknown,
            [0x34] = vm_cpuexit_unknown,
            [0x35] = vm_cpuexit_unknown,
            [0x36] = vm_cpuexit_unknown,
            [0x37] = vm_cpuexit_unknown,
            [0x38] = vm_cpuexit_unknown,
            [0x39] = vm_cpuexit_unknown,
            [0x3a] = vm_cpuexit_unknown,
            [0x3b] = vm_cpuexit_unknown,
            [0x3c] = vm_cpuexit_unknown,
            [0x3d] = vm_cpuexit_unknown,
            [0x3e] = vm_cpuexit_unknown,
            [0x3f] = vm_cpuexit_unknown,

            [SQUASH(WHvRunVpExitReasonMemoryAccess)] = vm_cpuexit_MemoryAccess,
            [SQUASH(WHvRunVpExitReasonX64IoPortAccess)] = vm_cpuexit_X64IoPortAccess,
            [SQUASH(WHvRunVpExitReasonCanceled)] = vm_cpuexit_Canceled,
        };
        int index = SQUASH(exit_context.ExitReason);
#undef SQUASH

        result = dispatch[index](instance, &exit_context);
        if (instance->debug_log_flags)
            vm_debug_log(cpu_index, &exit_context, result);
        if (!vm_result_check(result))
            goto exit;
    }

exit:
    if (!vm_result_check(result))
        InterlockedCompareExchange64(&instance->thread_result, result, VM_RESULT_SUCCESS);

    if (0 != next_thread)
        vm_thread_set_cancelled(next_thread);

    WHvCancelRunVirtualProcessor(instance->partition, (cpu_index + 1) % instance->config.cpu_count, 0);

    if (0 != next_thread)
    {
        WaitForSingleObject(next_thread, INFINITE);
        CloseHandle(next_thread);
    }

    if (has_cpu)
        WHvDeleteVirtualProcessor(instance->partition, cpu_index);

    return 0;
}

static vm_result_t vm_cpuexit_unknown(vm_t *instance, WHV_RUN_VP_EXIT_CONTEXT *exit_context)
{
    return vm_result(VM_ERROR_CANCELLED, 0);
}

static vm_result_t vm_cpuexit_MemoryAccess(vm_t *instance, WHV_RUN_VP_EXIT_CONTEXT *exit_context)
{
    return vm_result(VM_ERROR_CANCELLED, 0);
}

static vm_result_t vm_cpuexit_X64IoPortAccess(vm_t *instance, WHV_RUN_VP_EXIT_CONTEXT *exit_context)
{
    return vm_result(VM_ERROR_CANCELLED, 0);
}

static vm_result_t vm_cpuexit_Canceled(vm_t *instance, WHV_RUN_VP_EXIT_CONTEXT *exit_context)
{
    return vm_result(VM_ERROR_CANCELLED, 0);
}

static void vm_debug_log(UINT32 cpu_index, WHV_RUN_VP_EXIT_CONTEXT *exit_context, vm_result_t result)
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
    default:
        exit_reason_str = "?";
        break;
    }

    wsprintfA(buffer, "[%u] %s(cs:rip=%04x:%p, efl=%08x, pe=%d) = %d\n",
        (unsigned)cpu_index,
        exit_reason_str,
        exit_context->VpContext.Cs.Selector, exit_context->VpContext.Rip,
        (UINT32)exit_context->VpContext.Rflags,
        exit_context->VpContext.ExecutionState.Cr0Pe,
        (int)(vm_result_error(result) >> 48));
    buffer[sizeof buffer - 1] = '\0';
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), buffer, lstrlenA(buffer), &bytes, 0);
}
