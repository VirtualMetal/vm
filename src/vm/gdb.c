/**
 * @file vm/gdb.c
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

vm_result_t vm_gdb(vm_t *instance,
    vm_result_t (*strm)(void *strmdata, int dir, void *buffer, vm_count_t *plength),
    void *strmdata)
{
    return VM_RESULT_SUCCESS;
}
