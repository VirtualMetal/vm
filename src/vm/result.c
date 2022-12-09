/**
 * @file vm/result.c
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

#include <vm/internal.h>

const char *vm_result_error_string(vm_result_t result)
{
    switch (vm_result_error(result))
    {
    case VM_RESULT_SUCCESS:
        return "VM_RESULT_SUCCESS";
    case VM_ERROR_NOTIMPL:
        return "VM_ERROR_NOTIMPL";
    case VM_ERROR_MISUSE:
        return "VM_ERROR_MISUSE";
    case VM_ERROR_RESOURCES:
        return "VM_ERROR_RESOURCES";
    case VM_ERROR_FILE:
        return "VM_ERROR_FILE";
    case VM_ERROR_EXECFILE:
        return "VM_ERROR_EXECFILE";
    case VM_ERROR_CONFIG:
        return "VM_ERROR_CONFIG";
    case VM_ERROR_HYPERVISOR:
        return "VM_ERROR_HYPERVISOR";
    case VM_ERROR_MEMORY:
        return "VM_ERROR_MEMORY";
    case VM_ERROR_VCPU:
        return "VM_ERROR_VCPU";
    case VM_ERROR_TERMINATED:
        return "VM_ERROR_TERMINATED";
    default:
        return "VM_ERROR_<UNKNOWN>";
    }
}
