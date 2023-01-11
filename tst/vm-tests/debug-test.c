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

#include "vm-tests.h"

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

    result = vm_debug(instance, VM_DEBUG_ATTACH, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_BREAK, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    regl = sizeof regs;
    result = vm_debug(instance, VM_DEBUG_GETREGS, 0, 0, regs, &regl);
    ASSERT(vm_result_check(result));

    /* set rip = 2; skip over `jmp 0` instruction */
    regs[128] = 2;

    result = vm_debug(instance, VM_DEBUG_SETREGS, 0, 0, regs, &regl);
    ASSERT(vm_result_check(result));

    /* step over `nop` instruction */
    result = vm_debug(instance, VM_DEBUG_STEP, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_WAIT, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    regl = sizeof regs;
    result = vm_debug(instance, VM_DEBUG_GETREGS, 0, 0, regs, &regl);
    ASSERT(vm_result_check(result));

    /* assert rip == 3 */
    ASSERT(regs[128] == 3);

    /* step over `hlt` instruction; will cause termination */
    result = vm_debug(instance, VM_DEBUG_STEP, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_wait(instance);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_DETACH, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_delete(instance);
    ASSERT(vm_result_check(result));
}

static void vm_debug_mp_test(void)
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
    config.vcpu_count = 2;

    result = vm_run(&config, tconfigv, &instance);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_ATTACH, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_BREAK, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    regl = sizeof regs;
    result = vm_debug(instance, VM_DEBUG_GETREGS, 0, 0, regs, &regl);
    ASSERT(vm_result_check(result));

    /* set rip = 2; skip over `jmp 0` instruction */
    regs[128] = 2;

    result = vm_debug(instance, VM_DEBUG_SETREGS, 0, 0, regs, &regl);
    ASSERT(vm_result_check(result));

    /* step over `nop` instruction */
    result = vm_debug(instance, VM_DEBUG_STEP, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_WAIT, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    regl = sizeof regs;
    result = vm_debug(instance, VM_DEBUG_GETREGS, 0, 0, regs, &regl);
    ASSERT(vm_result_check(result));

    /* assert vcpu0 rip == 3 */
    ASSERT(regs[128] == 3);

    regl = sizeof regs;
    result = vm_debug(instance, VM_DEBUG_GETREGS, 1, 0, regs, &regl);
    ASSERT(vm_result_check(result));

    /* assert vcpu1 rip == 0 */
    ASSERT(regs[128] == 0);

    /* step over `hlt` instruction; will cause termination */
    result = vm_debug(instance, VM_DEBUG_STEP, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_wait(instance);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_DETACH, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_delete(instance);
    ASSERT(vm_result_check(result));
}

static void vm_debug_bp_test(void)
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
        "debug_break=1",
        "data=0,4,0x90,0x90,0x90,0xf4", /* nop; nop; nop; hlt */
        0,
    };
    vm_t *instance;
    char regs[1024];
    vm_count_t regl;
    unsigned char ins[1];
    vm_count_t insl;

    memset(&config, 0, sizeof config);
    config.vcpu_count = 1;

    result = vm_run(&config, tconfigv, &instance);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_SETBP, 0, 2, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_CONT, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_WAIT, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_DELBP, 0, 2, 0, 0);
    ASSERT(vm_result_check(result));

    regl = sizeof regs;
    result = vm_debug(instance, VM_DEBUG_GETREGS, 0, 0, regs, &regl);
    ASSERT(vm_result_check(result));

    /* assert rip == 2 */
    ASSERT(regs[128] == 2);

    result = vm_debug(instance, VM_DEBUG_SETBP, 0, 1, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_DETACH, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_wait(instance);
    ASSERT(vm_result_check(result));

    insl = sizeof ins;
    vm_mread(instance, 1, &ins, &insl);
    ASSERT(sizeof ins == insl);
    ASSERT(0x90 == ins[0]);

    result = vm_delete(instance);
    ASSERT(vm_result_check(result));
}

static void vm_debug_range_test(void)
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
        "debug_break=1",
        "data=0,4,0x90,0x90,0x90,0xf4", /* nop; nop; nop; hlt */
        0,
    };
    vm_t *instance;
    vm_debug_step_range_t step_range;
    vm_count_t length;
    char regs[1024];
    vm_count_t regl;

    memset(&config, 0, sizeof config);
    config.vcpu_count = 1;

    result = vm_run(&config, tconfigv, &instance);
    ASSERT(vm_result_check(result));

    step_range.begin = 0;
    step_range.end = 3;
    length = sizeof step_range;
    result = vm_debug(instance, VM_DEBUG_STEP, 0, 0, &step_range, &length);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_WAIT, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    regl = sizeof regs;
    result = vm_debug(instance, VM_DEBUG_GETREGS, 0, 0, regs, &regl);
    ASSERT(vm_result_check(result));

    /* assert rip == 3 */
    ASSERT(regs[128] == 3);

    /* step over `hlt` instruction; will cause termination */
    result = vm_debug(instance, VM_DEBUG_STEP, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_wait(instance);
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
    config.vcpu_count = 1;

    result = vm_run(&config, tconfigv, &instance);
    ASSERT(vm_result_check(result));

    result = vm_debug_server_start(instance, 0, "30317");
    ASSERT(vm_result_check(result));

#if !defined(_WIN64)
#define SOCKET int
#define INVALID_SOCKET (-1)
#define closesocket(s) close(s)
#endif
    SOCKET s;
    struct sockaddr_in addr =
    {
        .sin_family = AF_INET,
        .sin_port = htons(30317),
        .sin_addr.s_addr = htonl(0x7f000001),
    };
    int err;
    s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT(INVALID_SOCKET != s);
    err = connect(s, (void *)&addr, sizeof addr);
    ASSERT(0 == err);

    char *buffer;
#if defined(_WIN64)
    int PacketSize = 16 * 1024;
    int bytes;
#else
    size_t PacketSize = 16 * 1024;
    ssize_t bytes;
#endif
    buffer = malloc(PacketSize);
    ASSERT(0 != buffer);
    memset(buffer, 0, PacketSize);
    bytes = send(s, buffer, PacketSize, 0);
    ASSERT(PacketSize == bytes);
    memset(buffer, 0, PacketSize);
    buffer[0] = '$';
    bytes = send(s, buffer, PacketSize, 0);
    ASSERT(PacketSize == bytes);
    memset(buffer, 0, PacketSize);
    buffer[PacketSize - 1] = '$';
    bytes = send(s, buffer, PacketSize, 0);
    ASSERT(PacketSize == bytes);
    memcpy(buffer, "vMustReplyEmpty#3a", sizeof "vMustReplyEmpty#3a" - 1);
    bytes = send(s, buffer, sizeof "vMustReplyEmpty#3a" - 1, 0);
    ASSERT(sizeof "vMustReplyEmpty#3a" - 1 == bytes);
    bytes = recv(s, buffer, PacketSize, 0);
    ASSERT(1 <= bytes && '+' == buffer[0]);
    free(buffer);

#if defined(_WIN64)
    Sleep(300);
#else
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 300000000;
    nanosleep(&ts, 0);
#endif

    err = closesocket(s);
    ASSERT(0 == err);

    result = vm_debug_server_stop(instance);
    ASSERT(vm_result_check(result));

    result = vm_terminate(instance);
    ASSERT(vm_result_check(result));

    result = vm_wait(instance);
    ASSERT(vm_result_check(result));

    result = vm_delete(instance);
    ASSERT(vm_result_check(result));
}

static void vm_debug_cpuid_test(void)
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
        "debug_break=1",
        "data=0,8,0xb8,0x01,0x00,0x00,0x00,0x0f,0xa2,0xf4",
        0,
    };
    vm_t *instance;
    char regs[1024];
    vm_count_t regl;

    memset(&config, 0, sizeof config);
    config.vcpu_count = 1;

    result = vm_run(&config, tconfigv, &instance);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_SETBP, 0, 7, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_CONT, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_WAIT, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_debug(instance, VM_DEBUG_DELBP, 0, 7, 0, 0);
    ASSERT(vm_result_check(result));

    regl = sizeof regs;
    result = vm_debug(instance, VM_DEBUG_GETREGS, 0, 0, regs, &regl);
    ASSERT(vm_result_check(result));

    /* assert rip == 7 */
    ASSERT(regs[128] == 7);

    /* assert (rcx & 0x80000000); hypervisor present */
    ASSERT(regs[19] & 0x80);

    result = vm_debug(instance, VM_DEBUG_DETACH, 0, 0, 0, 0);
    ASSERT(vm_result_check(result));

    result = vm_wait(instance);
    ASSERT(vm_result_check(result));

    result = vm_delete(instance);
    ASSERT(vm_result_check(result));
}

void debug_tests(void)
{
    TEST(vm_debug_test);
    TEST(vm_debug_mp_test);
    TEST(vm_debug_bp_test);
    TEST(vm_debug_range_test);
    TEST(vm_debug_cpuid_test);
    TEST(vm_debug_server_test);
}
