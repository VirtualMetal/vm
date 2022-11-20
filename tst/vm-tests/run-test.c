/**
 * @file run-test.c
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

static void vm_create_delete_test(void)
{
    vm_result_t result;
    vm_config_t config;
    vm_t *instance;

    memset(&config, 0, sizeof config);
    config.vcpu_count = 1;

    result = vm_create(&config, &instance);
    ASSERT(vm_result_check(result));
    ASSERT(0 != instance);

    result = vm_delete(instance);
    ASSERT(vm_result_check(result));
}

static void vm_start_wait_test(void)
{
    vm_result_t result;
    vm_config_t config;
    vm_t *instance;

    memset(&config, 0, sizeof config);
    config.vcpu_count = 1;

    result = vm_create(&config, &instance);
    ASSERT(vm_result_check(result));
    ASSERT(0 != instance);

    result = vm_start(instance);
    ASSERT(vm_result_check(result));

    result = vm_wait(instance);
    ASSERT(VM_ERROR_MEMORY == vm_result_error(result));

    result = vm_delete(instance);
    ASSERT(vm_result_check(result));
}

static void vm_run_halt_test(void)
{
    vm_result_t result;
    vm_config_t config;
    char *text_config[] =
    {
        "mmap=0,0x10000",
        "pg0=0x1000",
        "pg1=0x2003",
        "pg2=0x0083,512",
        "vcpu_table=0x3000",
        "vcpu_entry=0x0000",
        "data=0,1,0xf4",
        0,
    };

    memset(&config, 0, sizeof config);
    config.vcpu_count = 1;

    result = vm_run(&config, text_config);
    ASSERT(vm_result_check(result));
}

void run_tests(void)
{
    TEST(vm_create_delete_test);
    TEST(vm_start_wait_test);
    TEST(vm_run_halt_test);
}