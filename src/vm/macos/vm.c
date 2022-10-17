/**
 * @file vm/macos/vm.c
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

struct vm
{
    vm_config_t config;
};

vm_result_t vm_create(const vm_config_t *config, vm_t **pinstance)
{
    return VM_ERROR_NOTIMPL;
}

vm_result_t vm_delete(vm_t *instance)
{
    return VM_ERROR_NOTIMPL;
}

vm_result_t vm_set_debug_log(vm_t *instance, unsigned flags)
{
    return VM_ERROR_NOTIMPL;
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
