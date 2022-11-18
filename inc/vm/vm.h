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
#define VM_ERROR_FILE                   (-4LL<<48)  /* file error (e.g. cannot find file) */
#define VM_ERROR_CONFIG                 (-5LL<<48)  /* configuration error */
#define VM_ERROR_HYPERVISOR             (-6LL<<48)  /* hypervisor error (e.g. not present) */
#define VM_ERROR_VCPU                   (-7LL<<48)  /* virtual cpu error (e.g. cannot create) */
#define VM_ERROR_TERMINATED             (-8LL<<48)  /* instance has terminated */

#define vm_result(e, r)                 ((vm_result_t)(e) | ((vm_result_t)(r) & VM_RESULT_REASON_MASK))
#define vm_result_error(R)              ((vm_result_t)(R) & VM_RESULT_ERROR_MASK)
#define vm_result_reason(R)             ((vm_result_t)(R) & VM_RESULT_REASON_MASK)
#define vm_result_check(R)              ((vm_result_t)(R) >= VM_RESULT_SUCCESS)

typedef struct vm vm_t;
typedef struct vm_config vm_config_t;
typedef struct vm_mmap vm_mmap_t;
typedef unsigned long long vm_count_t;

struct vm_config
{
    void (*debug_log)(const char *format, ...);
    vm_count_t vcpu_count;              /* number of virtual cpu's */
    vm_count_t vcpu_entry;              /* virtual cpu entry point */
    vm_count_t vcpu_table;              /* virtual cpu data table address */
    vm_count_t page_table;              /* page table address */

    vm_count_t reserved[59];
};

/**
 * Run a VM instance with the specified textual configuration.
 *
 * This function creates, configures and starts a new VM instance. It then
 * waits until the instance has stopped and then deletes the instance and
 * returns.
 *
 * @param default_config
 *     The default base configuration to use.
 * @param text_config
 *     The textual configuration to use.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_run(const vm_config_t *default_config, char **text_config);

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

/**
 * Map anonymous or file backed host memory to guest memory.
 *
 * @param instance
 *     The VM instance.
 * @param host_address
 *     The host address to map. If 0 then new host memory will be allocated.
 * @param file
 *     The file to map. If -1 then the host memory is not file backed.
 *     Otherwise the host memory is file backed; in this case it is an error
 *     to specify a non-0 host_address.
 * @param guest_address
 *     The guest address of the mapping.
 * @param length
 *     The length of the mapping. This parameter may not be 0.
 * @param pmap
 *     Pointer to location that will receive the new mapping.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_mmap(vm_t *instance,
    void *host_address, int file, vm_count_t guest_address, vm_count_t length,
    vm_mmap_t **pmap);

/**
 * Unmap a previous mapping of host memory to guest memory.
 *
 * @param instance
 *     The VM instance.
 * @param map
 *     The mapping.
 * @return
 *     VM_RESULT_SUCCESS.
 */
vm_result_t vm_munmap(vm_t *instance, vm_mmap_t *map);

/**
 * Read from a mapping.
 *
 * @param map
 *     The mapping.
 * @param offset
 *     The offset within the mapping to read from.
 * @param buffer
 *     The buffer to read into.
 * @param plength
 *     On input it contains the length of the buffer. On output it receives
 *     the number of bytes read.
 * @return
 *     VM_RESULT_SUCCESS.
 */
vm_result_t vm_mmap_read(vm_mmap_t *map,
    vm_count_t offset, void *buffer, vm_count_t *plength);

/**
 * Write to a mapping.
 *
 * @param map
 *     The mapping.
 * @param buffer
 *     The buffer to write from.
 * @param offset
 *     The offset within the mapping to write into.
 * @param plength
 *     On input it contains the length of the buffer. On output it receives
 *     the number of bytes written.
 * @return
 *     VM_RESULT_SUCCESS.
 */
vm_result_t vm_mmap_write(vm_mmap_t *map,
    void *buffer, vm_count_t offset, vm_count_t *plength);

/**
 * Read from guest memory.
 *
 * This function has some limitations:
 *
 * - It cannot be used to cross memory mapping boundaries. All accessed
 * memory must be contained within a single memory mapping.
 *
 * - It is intended to be used primarily for instance configuration and
 * should not be used on critical paths. It performs a linear search of
 * memory mappings and is slow.
 *
 * @param instance
 *     The VM instance.
 * @param guest_address
 *     The guest address to read from.
 * @param buffer
 *     The buffer to read into.
 * @param plength
 *     On input it contains the length of the buffer. On output it receives
 *     the number of bytes read.
 * @return
 *     VM_RESULT_SUCCESS.
 */
vm_result_t vm_mread(vm_t *instance,
    vm_count_t guest_address, void *buffer, vm_count_t *plength);

/**
 * Write to guest memory.
 *
 * This function has some limitations:
 *
 * - It cannot be used to cross memory mapping boundaries. All accessed
 * memory must be contained within a single memory mapping.
 *
 * - It is intended to be used primarily for instance configuration and
 * should not be used on critical paths. It performs a linear search of
 * memory mappings and is slow.
 *
 * @param instance
 *     The VM instance.
 * @param buffer
 *     The buffer to write from.
 * @param guest_address
 *     The guest address to write into.
 * @param plength
 *     On input it contains the length of the buffer. On output it receives
 *     the number of bytes written.
 * @return
 *     VM_RESULT_SUCCESS.
 */
vm_result_t vm_mwrite(vm_t *instance,
    void *buffer, vm_count_t guest_address, vm_count_t *plength);

/**
 * Start a VM instance.
 *
 * This function starts and runs the instance virtual CPU's. It handles
 * virtual CPU "exits" and forwards them to the appropriate vm_interface_t
 * methods.
 *
 * This function is not thread-safe in general, although it is thread-safe
 * against vm_terminate.
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
 * vm_terminate has been called.
 *
 * This function is not thread-safe in general, although it is thread-safe
 * against vm_terminate.
 *
 * @param instance
 *     The VM instance.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_wait(vm_t *instance);

/**
 * Terminate a VM instance.
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
vm_result_t vm_terminate(vm_t *instance);

#define VM_DEBUG_ATTACH                 ((vm_count_t)'A')   /**< attach debugger to VM instance */
#define VM_DEBUG_DETACH                 ((vm_count_t)'D')   /**< detach debugger from VM instance */
#define VM_DEBUG_BREAK                  ((vm_count_t)0x3)   /**< break into debugger */
#define VM_DEBUG_CONT                   ((vm_count_t)'c')   /**< continue the VM instance */
#define VM_DEBUG_STEP                   ((vm_count_t)'s')   /**< single step the VM instance */
#define VM_DEBUG_GETREGS                ((vm_count_t)'g')   /**< get registers (GDB format) */
#define VM_DEBUG_SETREGS                ((vm_count_t)'G')   /**< set registers (GDB format) */
#define VM_DEBUG_SETBP                  ((vm_count_t)'Z')   /**< set breakpoint */
#define VM_DEBUG_DELBP                  ((vm_count_t)'z')   /**< delete breakpoint */

typedef struct vm_debug_events vm_debug_events_t;
struct vm_debug_events
{
    void *self;
    void (*stop)(void *self, vm_t *instance, vm_count_t reserved);
};

/**
 * Debug a VM instance.
 *
 * This function controls the debugging functionality of the VM instance.
 *
 * This function is thread-safe.
 *
 * @param instance
 *     The VM instance.
 * @param control
 *     One of the VM_DEBUG_* codes.
 * @param vcpu_index
 *     The virtual CPU index. This parameter is used only for the
 *     STEP, GET*REG and SET*REG codes.
 * @param buffer
 *     The buffer to read/write into. This parameter is used only for the
 *     ATTACH, *REGS, and *BP codes.
 * @param plength
 *     On input it contains the length of the buffer. On output it receives
 *     the number of bytes read/written. This parameter is used only for the
 *     ATTACH, *REGS, and *BP codes.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_debug(vm_t *instance, vm_count_t control, vm_count_t vcpu_index,
    void *buffer, vm_count_t *plength);

#ifdef __cplusplus
}
#endif

#endif
