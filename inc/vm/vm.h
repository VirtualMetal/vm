/**
 * @file vm/vm.h
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

#ifndef VM_VM_H_INCLUDED
#define VM_VM_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#define VM_RESULT_SUCCESS               ((vm_result_t)0)
#define VM_ERROR_NOTIMPL                ((vm_result_t)-1LL<<32)    /* not implemented */
#define VM_ERROR_MISUSE                 ((vm_result_t)-2LL<<32)    /* function misuse (e.g. invalid args) */
#define VM_ERROR_MEMORY                 ((vm_result_t)-3LL<<32)    /* memory error (e.g. out of memory) */
#define VM_ERROR_HYPERVISOR             ((vm_result_t)-4LL<<32)    /* hypervisor error (e.g. not present) */
#define VM_ERROR_INSTANCE               ((vm_result_t)-5LL<<32)    /* instance error (e.g. cannot create) */
#define VM_ERROR_THREAD                 ((vm_result_t)-6LL<<32)    /* thread error (e.g. cannot create) */
#define VM_ERROR_CPU                    ((vm_result_t)-7LL<<32)    /* cpu error (e.g. cannot create) */
#define VM_ERROR_STOP                   ((vm_result_t)-8LL<<32)    /* stop processing */

typedef long long vm_result_t;

static inline
vm_result_t vm_make_result(vm_result_t error, vm_result_t reason)
{
    return error | (reason & (vm_result_t)0x00000000ffffffffULL);
}

static inline
vm_result_t vm_result_error(vm_result_t result)
{
    return result & (vm_result_t)0xffffffff00000000ULL;
}

static inline
vm_result_t vm_result_reason(vm_result_t result)
{
    return result & (vm_result_t)0x00000000ffffffffULL;
}

typedef struct vm vm_t;
typedef struct vm_config vm_config_t;
typedef struct vm_interface vm_interface_t;
typedef unsigned long long vm_count_t;

struct vm_config
{
    vm_interface_t *interface;
    vm_count_t cpu_count;
    vm_count_t memory_size;

    vm_count_t reserved[61];
};

struct vm_interface
{
    vm_result_t (*ioport)();
    vm_result_t (*memory)();

    vm_result_t (*reserved[30])();
};

vm_result_t vm_create(const vm_config_t *config, vm_t **pinstance);
vm_result_t vm_delete(vm_t *instance);
vm_result_t vm_set_debug_log(vm_t *instance, unsigned flags);
vm_result_t vm_start_dispatcher(vm_t *instance);
vm_result_t vm_wait_dispatcher(vm_t *instance);
vm_result_t vm_stop_dispatcher(vm_t *instance);

#ifdef __cplusplus
}
#endif

#endif
