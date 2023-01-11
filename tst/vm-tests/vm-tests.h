/**
 * @file vm-tests.h
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

#ifndef VM_TESTS_H_INCLUDED
#define VM_TESTS_H_INCLUDED

#include <vm/internal.h>
#include <tlib/testsuite.h>

static inline
vm_result_t hook_vm_create(const vm_config_t *config, vm_t **pinstance)
{
    vm_config_t c = *config;
    char *v;
    if (0 != (v = getenv("VM_TESTS_COMPAT_FLAGS")))
        c.compat_flags = strtoullint(v, 0, +1);
    return vm_create(&c, pinstance);
}
static inline
vm_result_t hook_vm_run(const vm_config_t *default_config, char **tconfigv, vm_t **pinstance)
{
    vm_config_t c = *default_config;
    char *v;
    if (0 != (v = getenv("VM_TESTS_COMPAT_FLAGS")))
        c.compat_flags = strtoullint(v, 0, +1);
    return vm_run(&c, tconfigv, pinstance);
}
#define vm_create                       hook_vm_create
#define vm_run                          hook_vm_run

#endif
