/**
 * @file vm/guest/guest.c
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
#include <vm/guest/guest.h>

vm_runcmd_t *vm_guest_runcmds(void)
{
    static vm_runcmd_t runcmds[] =
    {
        { .name = "*linux", .fn = vm_guest_linux_runcmd },
        { 0 },
    };
    return runcmds;
}
