/**
 * @file vmlinux/plugin.h
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

#ifndef VMLINUX_PLUGIN_H_INCLUDED
#define VMLINUX_PLUGIN_H_INCLUDED

#include <vm/internal.h>

VM_API_EXPORT
vm_plugin_runcmds_t vm_plugin_runcmds;

vm_result_t vm_plugin_linux_runcmd(void *context,
    vm_runcmd_t *runcmd, char phase, const char *value);

#endif
