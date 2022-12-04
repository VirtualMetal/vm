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

static void vm_mmap_test(void)
{
    vm_result_t result;
    vm_config_t config;
    vm_t *instance;
    vm_mmap_t *map;
    vm_count_t value, length;

    memset(&config, 0, sizeof config);
    config.vcpu_count = 1;

    result = vm_create(&config, &instance);
    ASSERT(vm_result_check(result));
    ASSERT(0 != instance);

    result = vm_mmap(instance, 0, -1, 0, 1024 * 1024, &map);
    ASSERT(vm_result_check(result));
    ASSERT(0 != map);

    value = 0x0123456789abcdefULL;
    length = sizeof value;
    result = vm_mwrite(instance, &value, 0, &length);
    ASSERT(vm_result_check(result));
    ASSERT(sizeof value == length);

    value = 0xfedcba9876543210ULL;
    length = sizeof value;
    result = vm_mwrite(instance, &value, 1024 * 1024 - sizeof value, &length);
    ASSERT(vm_result_check(result));
    ASSERT(sizeof value == length);

    length = sizeof value;
    result = vm_mread(instance, 0, &value, &length);
    ASSERT(vm_result_check(result));
    ASSERT(sizeof value == length);
    ASSERT(0x0123456789abcdefULL == value);

    length = sizeof value;
    result = vm_mread(instance, 1024 * 1024 - sizeof value, &value, &length);
    ASSERT(vm_result_check(result));
    ASSERT(sizeof value == length);
    ASSERT(0xfedcba9876543210ULL == value);

    result = vm_delete(instance);
    ASSERT(vm_result_check(result));
}

static void vm_mmap_file_test(void)
{
    vm_result_t result;
    vm_config_t config;
    vm_t *instance;
    vm_mmap_t *map;
    vm_count_t value, length;
    char *fileA = "./vm-tests-fileA";
    char *dataA = "TESTFILETESTFILE";
    int file;
    ssize_t bytes;

    memset(&config, 0, sizeof config);
    config.vcpu_count = 1;

    result = vm_create(&config, &instance);
    ASSERT(vm_result_check(result));
    ASSERT(0 != instance);

    file = open(fileA, O_RDWR | O_CREAT | O_EXCL, 0666);
    ASSERT(-1 != file);
    bytes = pwrite(file, dataA, strlen(dataA), 0);
    ASSERT(strlen(dataA) == bytes);
    close(file);

    file = open(fileA, O_RDONLY);
    ASSERT(-1 != file);
    result = vm_mmap(instance, 0, file, 0, 1024 * 1024, &map);
    ASSERT(vm_result_check(result));
    ASSERT(0 != map);
    close(file);

    length = sizeof value;
    result = vm_mread(instance, 0, &value, &length);
    ASSERT(vm_result_check(result));
    ASSERT(sizeof value == length);
    ASSERT(0 == memcmp(&value, dataA, sizeof value));
    length = sizeof value;
    result = vm_mread(instance, sizeof value, &value, &length);
    ASSERT(vm_result_check(result));
    ASSERT(sizeof value == length);
    ASSERT(0 == memcmp(&value, dataA + sizeof value, sizeof value));

    value = 0x0123456789abcdefULL;
    length = sizeof value;
    result = vm_mwrite(instance, &value, 0, &length);
    ASSERT(vm_result_check(result));
    ASSERT(sizeof value == length);

    value = 0x0123456776543210ULL;
    length = sizeof value;
    result = vm_mwrite(instance, &value, 4096-4, &length);
    ASSERT(vm_result_check(result));
    ASSERT(sizeof value == length);

    value = 0xfedcba9876543210ULL;
    length = sizeof value;
    result = vm_mwrite(instance, &value, 1024 * 1024 - sizeof value, &length);
    ASSERT(vm_result_check(result));
    ASSERT(sizeof value == length);

    length = sizeof value;
    result = vm_mread(instance, 0, &value, &length);
    ASSERT(vm_result_check(result));
    ASSERT(sizeof value == length);
    ASSERT(0x0123456789abcdefULL == value);
    length = sizeof value;
    result = vm_mread(instance, sizeof value, &value, &length);
    ASSERT(vm_result_check(result));
    ASSERT(sizeof value == length);
    ASSERT(0 == memcmp(&value, dataA + sizeof value, sizeof value));

    length = sizeof value;
    result = vm_mread(instance, 4096-4, &value, &length);
    ASSERT(vm_result_check(result));
    ASSERT(sizeof value == length);
    ASSERT(0x0123456776543210ULL == value);

    length = sizeof value;
    result = vm_mread(instance, 1024 * 1024 - sizeof value, &value, &length);
    ASSERT(vm_result_check(result));
    ASSERT(sizeof value == length);
    ASSERT(0xfedcba9876543210ULL == value);

    result = vm_delete(instance);
    ASSERT(vm_result_check(result));

    unlink(fileA);
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

static void vm_run_error_test(void)
{
    vm_result_t result;
    vm_config_t config;
    char *tconfigv[] =
    {
        "badconfig",
        0,
    };
    vm_t *instance;

    memset(&config, 0, sizeof config);

    result = vm_run(&config, tconfigv, &instance);
    ASSERT(VM_ERROR_CONFIG == vm_result_error(result) && 1 == vm_result_reason(result));
}

static void vm_run_halt_test(void)
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
        "data=0,1,0xf4",
        0,
    };
    vm_t *instance;

    memset(&config, 0, sizeof config);
    config.vcpu_count = 1;

    result = vm_run(&config, tconfigv, &instance);
    ASSERT(vm_result_check(result));

    result = vm_wait(instance);
    ASSERT(vm_result_check(result));

    result = vm_delete(instance);
    ASSERT(vm_result_check(result));
}

static void vm_run_terminate_test(void)
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

#if defined(_WIN64)
    Sleep(300);
#else
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 300000000;
    nanosleep(&ts, 0);
#endif

    result = vm_terminate(instance);
    ASSERT(vm_result_check(result));

    result = vm_wait(instance);
    ASSERT(vm_result_check(result));

    result = vm_delete(instance);
    ASSERT(vm_result_check(result));
}

void run_tests(void)
{
    TEST(vm_create_delete_test);
    TEST(vm_mmap_test);
    TEST(vm_mmap_file_test);
    TEST(vm_start_wait_test);
    TEST(vm_run_error_test);
    TEST(vm_run_halt_test);
    TEST(vm_run_terminate_test);
}
