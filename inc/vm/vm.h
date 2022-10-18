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

typedef long long vm_result_t;

#define VM_RESULT_SUCCESS               (0LL)
#define VM_RESULT_REASON_MASK           ((1LL << 48) - 1LL)
#define VM_RESULT_ERROR_MASK            (~VM_RESULT_REASON_MASK)

#define VM_ERROR_NOTIMPL                (-1LL<<48)  /* not implemented */
#define VM_ERROR_MISUSE                 (-2LL<<48)  /* function misuse (e.g. invalid args) */
#define VM_ERROR_MEMORY                 (-3LL<<48)  /* memory error (e.g. out of memory) */
#define VM_ERROR_THREAD                 (-4LL<<48)  /* thread error (e.g. cannot create) */
#define VM_ERROR_HYPERVISOR             (-5LL<<48)  /* hypervisor error (e.g. not present) */
#define VM_ERROR_INSTANCE               (-6LL<<48)  /* vm instance error (e.g. cannot create) */
#define VM_ERROR_CPU                    (-7LL<<48)  /* cpu error (e.g. cannot create) */
#define VM_ERROR_STOP                   (-8LL<<48)  /* stop processing */

#define vm_result_make(e, r)            ((vm_result_t)(e) | ((vm_result_t)(r) & VM_RESULT_REASON_MASK))
#define vm_result_error(R)              ((vm_result_t)(R) & VM_RESULT_ERROR_MASK)
#define vm_result_reason(R)             ((vm_result_t)(R) & VM_RESULT_REASON_MASK)
#define vm_result_success(R)            ((vm_result_t)(R) >= VM_RESULT_SUCCESS)

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
