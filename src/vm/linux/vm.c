/**
 * @file vm/linux/vm.c
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
#include <linux/kvm.h>

struct vm
{
    vm_config_t config;
    int hvfd;
    int vmfd;
    void *memory;
    int memory_set;
    unsigned debug_log_flags;
    pthread_t dispatcher_thread;
    unsigned dispatcher_thread_count;
};

static void *vm_dispatcher_thread(void *instance0);

vm_result_t vm_create(const vm_config_t *config, vm_t **pinstance)
{
    vm_result_t result;
    vm_t *instance = 0;

    *pinstance = 0;

    instance = malloc(sizeof *instance);
    if (0 == instance)
    {
        result = VM_ERROR_MEMORY;
        goto exit;
    }

    memset(instance, 0, sizeof *instance);
    instance->config = *config;
    instance->hvfd = -1;
    instance->vmfd = -1;
    instance->memory = MAP_FAILED;

    if (0 == instance->config.cpu_count)
    {
        cpu_set_t affinity;
        CPU_ZERO(&affinity);
        if (-1 == sched_getaffinity(0, sizeof affinity, &affinity))
        {
            result = vm_result(VM_ERROR_INSTANCE, errno);
            goto exit;
        }
        instance->config.cpu_count = (vm_count_t)CPU_COUNT(&affinity);
    }
    if (0 == instance->config.cpu_count)
        instance->config.cpu_count = 1;

    instance->hvfd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (-1 == instance->hvfd)
    {
        result = vm_result(VM_ERROR_HYPERVISOR, errno);
        goto exit;
    }

    if (12 != ioctl(instance->hvfd, KVM_GET_API_VERSION, NULL))
    {
        result = VM_ERROR_HYPERVISOR;
        goto exit;
    }

    if (0 >= ioctl(instance->hvfd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY))
    {
        result = VM_ERROR_HYPERVISOR;
        goto exit;
    }

    instance->vmfd = ioctl(instance->hvfd, KVM_CREATE_VM, NULL);
    if (-1 == instance->vmfd)
    {
        result = vm_result(VM_ERROR_INSTANCE, errno);
        goto exit;
    }

    instance->memory = mmap(
        0, instance->config.memory_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (MAP_FAILED == instance->memory)
    {
        result = vm_result(VM_ERROR_MEMORY, errno);
        goto exit;
    }

    struct kvm_userspace_memory_region region;
    memset(&region, 0, sizeof region);
    region.guest_phys_addr = 0;
    region.memory_size = instance->config.memory_size;
    region.userspace_addr = (__u64)instance->memory;
    if (-1 == ioctl(instance->vmfd, KVM_SET_USER_MEMORY_REGION, &region))
    {
        result = vm_result(VM_ERROR_INSTANCE, errno);
        goto exit;
    }
    instance->memory_set = 1;

    *pinstance = instance;
    result = VM_RESULT_SUCCESS;

exit:
    if (!vm_result_check(result) && 0 != instance)
        vm_delete(instance);

    return result;
}

vm_result_t vm_delete(vm_t *instance)
{
    if (instance->memory_set)
    {
        struct kvm_userspace_memory_region region;
        memset(&region, 0, sizeof region);
        ioctl(instance->vmfd, KVM_SET_USER_MEMORY_REGION, &region);
    }

    if (MAP_FAILED != instance->memory)
        munmap(instance->memory, instance->config.memory_size);

    if (-1 != instance->vmfd)
        close(instance->vmfd);

    if (-1 != instance->hvfd)
        close(instance->hvfd);

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
    int error;

    if (0 != instance->dispatcher_thread)
    {
        result = VM_ERROR_MISUSE;
        goto exit;
    }

    instance->dispatcher_thread_count = (unsigned)instance->config.cpu_count;
    error = pthread_create(&instance->dispatcher_thread, 0, vm_dispatcher_thread, instance);
    if (0 != error)
    {
        result = vm_result(VM_ERROR_THREAD, error);
        goto exit;
    }

    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

vm_result_t vm_wait(vm_t *instance)
{
    return VM_ERROR_NOTIMPL;
}

vm_result_t vm_stop(vm_t *instance)
{
    return VM_ERROR_NOTIMPL;
}

static void *vm_dispatcher_thread(void *instance0)
{
    return 0;
#if 0
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
            result = vm_result(VM_ERROR_THREAD, GetLastError());
            goto exit;
        }
    }

    hresult = WHvCreateVirtualProcessor(instance->partition, cpu_index, 0);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_CPU, hresult);
        goto exit;
    }
    cpu_created = TRUE;

    for (;;)
    {
        hresult = WHvRunVirtualProcessor(instance->partition,
            cpu_index, &exit_context, sizeof exit_context);
        if (FAILED(hresult))
        {
            result = vm_result(VM_ERROR_CPU, hresult);
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
        if (!vm_result_check(result))
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
#endif
}
