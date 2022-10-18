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
};

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

vm_result_t vm_start_dispatcher(vm_t *instance)
{
    return VM_ERROR_NOTIMPL;
}

vm_result_t vm_wait_dispatcher(vm_t *instance)
{
    return VM_ERROR_NOTIMPL;
}

vm_result_t vm_stop_dispatcher(vm_t *instance)
{
    return VM_ERROR_NOTIMPL;
}
