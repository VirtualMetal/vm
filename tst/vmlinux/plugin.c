/**
 * @file vmlinux/plugin.c
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

#include <vmlinux/plugin.h>

VM_API_EXPORT
vm_runcmd_t *vm_plugin_runcmds(void)
{
    static vm_runcmd_t runcmds[] =
    {
        { .name = "*linux", .fn = vm_plugin_linux_runcmd },
        { 0 },
    };
    return runcmds;
}

LIBMAIN;
