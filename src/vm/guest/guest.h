/**
 * @file vm/guest/guest.h
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

#ifndef VM_GUEST_GUEST_H_INCLUDED
#define VM_GUEST_GUEST_H_INCLUDED

vm_result_t vm_guest_linux_runcmd(void *context,
    vm_runcmd_t *runcmd, char phase, const char *value);

vm_runcmd_t *vm_guest_runcmds();

#endif
