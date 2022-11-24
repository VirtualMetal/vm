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
        "data=0,4,0xeb,0xfe,0x90,0xf4", /* jmp 0; nop; hlt */
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

    /* set rip = 2; skip over `jmp 0` instruction */
    regs[128] = 2;

    result = vm_debug(instance, VM_DEBUG_SETREGS, 0, regs, &regl);
    ASSERT(vm_result_check(result));

    /* step over `nop` instruction */
    result = vm_debug(instance, VM_DEBUG_STEP, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_WAIT, 0, 0, 0);
    ASSERT(vm_result_check(result));

    regl = sizeof regs;
    result = vm_debug(instance, VM_DEBUG_GETREGS, 0, regs, &regl);
    ASSERT(vm_result_check(result));

    /* assert rip == 3 */
    ASSERT(regs[128] == 3);

    /* step over `hlt` instruction; will cause termination */
    result = vm_debug(instance, VM_DEBUG_STEP, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_wait(instance);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_DETACH, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_delete(instance);
    ASSERT(vm_result_check(result));
}

static void vm_debug_server_test(void)
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
        "data=0,2,0xeb,0xfe",           /* jmp 0 */
        0,
    };
    vm_t *instance;

    memset(&config, 0, sizeof config);
    config.vcpu_count = 0;

    result = vm_run(&config, tconfigv, &instance);
    ASSERT(vm_result_check(result));

    result = vm_debug_server_start(instance, 0, ":28022");
    ASSERT(vm_result_check(result));

#if defined(_WIN64)
    Sleep(300);
#else
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 300000000;
    nanosleep(&ts, 0);
#endif

    result = vm_debug_server_stop(instance);
    ASSERT(vm_result_check(result));

    result = vm_terminate(instance);
    ASSERT(vm_result_check(result));

    result = vm_wait(instance);
    ASSERT(vm_result_check(result));

    result = vm_delete(instance);
    ASSERT(vm_result_check(result));
}

void debug_tests(void)
{
    TEST(vm_debug_test);
    if (0)
        TEST(vm_debug_server_test);
}
