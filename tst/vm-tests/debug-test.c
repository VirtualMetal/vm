/**
 * @file debug-test.c
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
#include <tlib/testsuite.h>

static void vm_debug_test(void)
{
    vm_result_t result;
    vm_config_t config;
    char *tconfigv[] =
    {
        "mmap=0,0x10000",
        "pg0=0x1000",
        "pg1=0x2003",
        "pg2=0x0083,512",
        "vcpu_table=0x3000",
        "vcpu_entry=0x0000",
        "data=0,3,0xeb,0xfe,0xf4",      /* jmp 0; hlt */
        0,
    };
    vm_t *instance;
    char regs[1024];
    vm_count_t regl;

    memset(&config, 0, sizeof config);
    config.vcpu_count = 1;

    result = vm_run(&config, tconfigv, &instance);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_ATTACH, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_BREAK, 0, 0, 0);
    ASSERT(vm_result_check(result));

    regl = sizeof regs;
    result = vm_debug(instance, VM_DEBUG_GETREGS, 0, regs, &regl);
    ASSERT(vm_result_check(result));

    regs[128] = 2; /* rip = 2 */

    result = vm_debug(instance, VM_DEBUG_SETREGS, 0, regs, &regl);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_STEP, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_wait(instance);
    ASSERT(vm_result_check(result));

    result = vm_delete(instance);
    ASSERT(vm_result_check(result));
}

void debug_tests(void)
{
    TEST(vm_debug_test);
}
