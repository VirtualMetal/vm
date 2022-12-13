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
#define VM_ERROR_RESOURCES              (-3LL<<48)  /* insufficient resources (e.g. out of memory) */
#define VM_ERROR_FILE                   (-4LL<<48)  /* file error (e.g. cannot find file) */
#define VM_ERROR_EXECFILE               (-5LL<<48)  /* executable file error (e.g. bad file format) */
#define VM_ERROR_NETWORK                (-6LL<<48)  /* network error (e.g. cannot connect) */
#define VM_ERROR_CONFIG                 (-7LL<<48)  /* configuration error */
#define VM_ERROR_HYPERVISOR             (-8LL<<48)  /* hypervisor error (e.g. not present) */
#define VM_ERROR_MEMORY                 (-9LL<<48)  /* memory error (e.g. invalid address) */
#define VM_ERROR_VCPU                   (-10LL<<48) /* virtual cpu error (e.g. cannot create) */
#define VM_ERROR_TERMINATED             (-11LL<<48) /* instance has terminated */

#define vm_result(e, r)                 ((vm_result_t)(e) | ((vm_result_t)(r) & VM_RESULT_REASON_MASK))
#define vm_result_error(R)              ((vm_result_t)(R) & VM_RESULT_ERROR_MASK)
#define vm_result_reason(R)             ((vm_result_t)(R) & VM_RESULT_REASON_MASK)
#define vm_result_check(R)              ((vm_result_t)(R) >= VM_RESULT_SUCCESS)

const char *vm_result_error_string(vm_result_t result);

typedef struct vm vm_t;
typedef struct vm_config vm_config_t;
typedef struct vm_mmap vm_mmap_t;
typedef unsigned long long vm_count_t;

struct vm_config
{
    /* immutable */
    void (*logf)(const char *format, ...);
    vm_count_t log_flags;
    vm_count_t vcpu_count;              /* number of virtual cpu's */
    vm_count_t reserved0[5];

    /* reconfigurable */
    vm_count_t vcpu_entry;              /* virtual cpu entry point */
    vm_count_t vcpu_table;              /* virtual cpu data table address */
    vm_count_t page_table;              /* page table address */
    vm_count_t exec_textseg;            /* executable file text segment address */
    vm_count_t exec_dataseg;            /* executable file data segment address */
    vm_count_t reserved1[19];
};

#define VM_CONFIG_INDEX(F)              ((vm_count_t)&((vm_config_t *)0)->F / sizeof(vm_count_t))
#define VM_CONFIG_BIT(F)                (1 << VM_CONFIG_INDEX(F))
#define VM_CONFIG_FIELD(C, I)           ((vm_count_t *)((char *)(C) + I * sizeof(vm_count_t)))
#define VM_CONFIG_RECONFIG_MASK         (0xffffff00ULL)

#define VM_CONFIG_LOG_HYPERVISOR        1
#define VM_CONFIG_LOG_DEBUGSERVER       0x80000000

/**
 * Run a VM instance with the specified text configuration.
 *
 * This function creates, configures and starts a new VM instance.
 *
 * @param default_config
 *     The default base configuration to use.
 * @param tconfigv
 *     The text configuration to use.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_run(const vm_config_t *default_config, char **tconfigv, vm_t **pinstance);

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
 * This function is thread-safe if instance remains valid during the call.
 *
 * @param instance
 *     The VM instance.
 * @param guest_address
 *     The guest address of the mapping.
 * @param length
 *     The length of the mapping. This parameter may not be 0.
 * @param host_address
 *     The host address to map. If 0 then new host memory will be allocated.
 * @param file
 *     The file to map. If -1 then the host memory is not file backed.
 *     Otherwise the host memory is file backed; in this case it is an error
 *     to specify a non-0 host_address.
 * @param file_offset
 *     The offset within the file to map. This parameter should be 0 if the
 *     file parameter is -1.
 * @param file_length
 *     The length of the file to map. If this parameter is 0 then this is the
 *     same as the length parameter. Otherwise this parameter must be less
 *     than or equal to the length parameter. This parameter should be 0 if
 *     the file parameter is -1.
 * @param pmap
 *     Pointer to location that will receive the new mapping.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_mmap(vm_t *instance,
    vm_count_t guest_address, vm_count_t length,
    void *host_address, int file, vm_count_t file_offset, vm_count_t file_length,
    vm_mmap_t **pmap);

/**
 * Unmap a previous mapping of host memory to guest memory.
 *
 * This function is thread-safe if instance remains valid during the call.
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
 * This function is thread-safe if instance remains valid during the call.
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
 * This function is thread-safe if instance remains valid during the call.
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
 * Reconfigure a VM instance.
 *
 * Reconfiguration is possible only if the instance has not been started.
 * Not all configuration fields can be updated.
 *
 * This function is thread-safe if instance remains valid during the call.
 *
 * @param instance
 *     The VM instance.
 * @param config
 *     The new configuration to use.
 * @param mask
 *     Specifies which configuration fields to update. Not all configuration
 *     fields can be updated.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_reconfig(vm_t *instance, const vm_config_t *config, vm_count_t mask);

/**
 * Start a VM instance.
 *
 * This function starts and runs the instance virtual CPU's. It handles
 * virtual CPU "exits" and forwards them to the appropriate vm_interface_t
 * methods.
 *
 * This function is thread-safe if instance remains valid during the call.
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
 * This function is thread-safe if instance remains valid during the call.
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
 * This function is thread-safe if instance remains valid during the call.
 *
 * @param instance
 *     The VM instance.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_terminate(vm_t *instance);

#define VM_DEBUG_ATTACH                 ((vm_count_t)'A')   /**< attach debugger to VM instance */
#define VM_DEBUG_DETACH                 ((vm_count_t)'D')   /**< detach debugger from VM instance */
#define VM_DEBUG_SETEVENTS              ((vm_count_t)'E')   /**< set debug events handler */
#define VM_DEBUG_BREAK                  ((vm_count_t)0x3)   /**< break into debugger */
#define VM_DEBUG_WAIT                   ((vm_count_t)'w')   /**< wait until VM instance stops */
#define VM_DEBUG_CONT                   ((vm_count_t)'c')   /**< continue the VM instance */
#define VM_DEBUG_STEP                   ((vm_count_t)'s')   /**< single step the VM instance */
#define VM_DEBUG_GETREGS                ((vm_count_t)'g')   /**< get registers (GDB format) */
#define VM_DEBUG_SETREGS                ((vm_count_t)'G')   /**< set registers (GDB format) */
#define VM_DEBUG_GETVMEM                ((vm_count_t)'m')   /**< get virtual memory (GDB format) */
#define VM_DEBUG_SETVMEM                ((vm_count_t)'M')   /**< set virtual memory (GDB format) */
#define VM_DEBUG_SETBP                  ((vm_count_t)'Z')   /**< set breakpoint */
#define VM_DEBUG_DELBP                  ((vm_count_t)'z')   /**< delete breakpoint */

typedef struct vm_debug_events vm_debug_events_t;
struct vm_debug_events
{
    void *self;
    void (*handler)(void *self, vm_t *instance, vm_count_t control, vm_count_t reserved);
};

/**
 * Debug a VM instance.
 *
 * This function controls the debugging functionality of the VM instance.
 *
 * This function is thread-safe if instance remains valid during the call.
 *
 * @param instance
 *     The VM instance.
 * @param control
 *     One of the VM_DEBUG_* codes.
 * @param vcpu_index
 *     The virtual CPU index. This parameter is used only for the
 *     *REGS, *VMEM, and *BP codes.
 * @param address
 *     The guest address. If the vcpu_index parameter is ~0ULL, this is
 *     interpretted as a physical address, else it is interpretted as a
 *     virtual address. This parameter is used only for the
 *     *VMEM, and *BP codes.
 * @param buffer
 *     The buffer to read/write into. This parameter is used only for the
 *     SETEVENTS, *REGS, and *VMEM codes.
 * @param plength
 *     On input it contains the length of the buffer. On output it receives
 *     the number of bytes read/written. This parameter is used only for the
 *     SETEVENTS, *REGS, and *VMEM codes.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_debug(vm_t *instance,
    vm_count_t control, vm_count_t vcpu_index, vm_count_t address,
    void *buffer, vm_count_t *plength);

/**
 * Start a debug server.
 *
 * This function starts a debug server that listens on the specified network
 * interface for GDB protocol commands.
 *
 * This function is thread-safe if instance remains valid during the call.
 *
 * @param instance
 *     The VM instance.
 * @param hostname
 *     The host name or numeric IPv4 or IPv6 address.
 * @param servname
 *     The service name or port number.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_debug_server_start(vm_t *instance,
    const char *hostname, const char *servname);

/**
 * Stop a debug server.
 *
 * This function stops the debug server if any.
 *
 * This function is thread-safe if instance remains valid during the call.
 *
 * @param instance
 *     The VM instance.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_debug_server_stop(vm_t *instance);

/**
 * Debug a VM instance via the GDB remote protocol.
 *
 * This function is thread-safe if instance remains valid during the call.
 *
 * @param instance
 *     The VM instance.
 * @param strm
 *     This function pointer is used to communicate with the remote client.
 *     The dir parameter controls the communication direction and takes values
 *     as follows: (+1) receive data, (-1) send data, and (-2) send OOB data.
 * @param strmdata
 *     Data to use when calling strm.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_gdb(vm_t *instance,
    vm_result_t (*strm)(void *strmdata, int dir, void *buffer, vm_count_t *plength),
    void *strmdata);

/**
 * Load executable file into guest memory.
 *
 * This function is thread-safe if instance remains valid during the call.
 *
 * @param instance
 *     The VM instance.
 * @param guest_address
 *     The guest address of an additional mapping around the loaded file.
 * @param length
 *     The length of an additional mapping around the loaded file. If this
 *     parameter is 0 then there is no additional mapping.
 * @param file
 *     The file to load.
 * @param exec_flag
 *     If 1 instance will execute the file upon start.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_load(vm_t *instance,
    vm_count_t guest_address, vm_count_t length,
    int file, int exec_flag);

/**
 * Parse text configuration.
 *
 * @param ptconfigc
 *     On input it contains the count of input configuration items. On output
 *     it receives the count of output configuration items.
 * @param ptconfigv
 *     On input it contains the input configuration items. On output it
 *     receives the output configuration items. If the output value is
 *     different from the input value, the output value must be freed using
 *     vm_free_text_config.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_parse_text_config(int *ptconfigc, char ***ptconfigv);

/**
 * Free text configuration.
 *
 * @param tconfigv
 *     The text configuration to free, which must have been returned by
 *     vm_parse_text_config.
 * @return
 *     VM_RESULT_SUCCESS or error code.
 */
vm_result_t vm_free_text_config(char **tconfigv);

#ifdef __cplusplus
}
#endif

#endif
