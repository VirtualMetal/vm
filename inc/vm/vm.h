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
#define VM_ERROR_HYPERVISOR             (-4LL<<48)  /* hypervisor error (e.g. not present) */
#define VM_ERROR_VCPU                   (-5LL<<48)  /* virtual cpu error (e.g. cannot create) */
#define VM_ERROR_CANCELLED              (-6LL<<48)  /* processing has been cancelled */

#define vm_result(e, r)                 ((vm_result_t)(e) | ((vm_result_t)(r) & VM_RESULT_REASON_MASK))
#define vm_result_error(R)              ((vm_result_t)(R) & VM_RESULT_ERROR_MASK)
#define vm_result_reason(R)             ((vm_result_t)(R) & VM_RESULT_REASON_MASK)
#define vm_result_check(R)              ((vm_result_t)(R) >= VM_RESULT_SUCCESS)

typedef struct vm vm_t;
typedef struct vm_config vm_config_t;
typedef struct vm_interface vm_interface_t;
typedef unsigned long long vm_count_t;

struct vm_config
{
    vm_interface_t *interface;
    vm_count_t vcpu_count;
    vm_count_t memory_size;

    vm_count_t reserved[61];
};

struct vm_interface
{
    vm_result_t (*ioport)();
    vm_result_t (*memory)();

    vm_result_t (*reserved[30])();
};

/**
 * Create a new VM instance with the specified configuration.
 *
 * @param config
 *     The VM configuration to use.
 * @param pinstance
 *     Pointer to location that will receive the new VM instance.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_create(const vm_config_t *config, vm_t **pinstance);
/**
 * Delete a VM instance.
 *
 * @param instance
 *     The VM instance.
 * @return
 *     VM_RESULT_SUCCESS.
 */
vm_result_t vm_delete(vm_t *instance);
vm_result_t vm_set_debug_log(vm_t *instance, unsigned flags);
/**
 * Start a VM instance.
 *
 * This function starts and runs the instance virtual CPU's. It handles
 * virtual CPU "exits" and forwards them to the appropriate vm_interface_t
 * methods.
 *
 * This function is not thread-safe in general, although it is thread-safe
 * against vm_cancel.
 *
 * @param instance
 *     The VM instance.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_start(vm_t *instance);
/**
 * Wait for a VM instance.
 *
 * This function waits until all the instance virtual CPU's have stopped.
 * Virtual CPU's stop either because of an unhandled "exit" or because
 * vm_cancel has been called.
 *
 * This function is not thread-safe in general, although it is thread-safe
 * against vm_cancel.
 *
 * @param instance
 *     The VM instance.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_wait(vm_t *instance);
/**
 * Cancel a VM instance.
 *
 * This function stops all instance virtual CPU's asynchronously. There is
 * no guarantee that the virtual CPU's have already been stopped when this
 * function returns.
 *
 * This function is thread-safe.
 *
 * @param instance
 *     The VM instance.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_cancel(vm_t *instance);

#ifdef __cplusplus
}
#endif

#endif
