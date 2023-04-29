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

typedef struct ioapic ioapic_t;
vm_result_t ioapic_create(vm_t *instance, ioapic_t **papic);
vm_result_t ioapic_delete(ioapic_t *apic);
vm_result_t ioapic_io(ioapic_t *apic, vm_count_t flags, vm_count_t address, void *buffer);
vm_result_t ioapic_irq(ioapic_t *apic, vm_count_t irq);

typedef struct serial serial_t;
vm_result_t serial_create(int fd[2], ioapic_t *apic, vm_count_t irq, serial_t **pport);
vm_result_t serial_delete(serial_t *port);
vm_result_t serial_io(serial_t *port, vm_count_t flags, vm_count_t address, void *buffer);

#endif
