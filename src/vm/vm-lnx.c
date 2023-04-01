/**
 * @file vm/vm-lnx.c
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
#include <linux/kvm.h>

/* our own signals -- do not use SIGRTMAX, which is used by valgrind */
#define SIG_VCPU_CANCEL                 (SIGRTMAX - 1)
#define SIG_DBSRV_CANCEL                (SIGRTMAX - 2)

#if defined(__x86_64__)
#define VM_DEBUG_BP_INSTR               0xcc    /* INT3 instruction */
#define VM_DEBUG_BP_LENGTH              1
#endif

struct vm
{
    vm_config_t config;                 /* must be first */
    int hv_fd;
    int vm_fd;
    int vcpu_run_size;
    pthread_mutex_t mmap_lock;
    list_link_t mmap_list;              /* protected by mmap_lock */
    bmap_t slot_bmap[bmap_declcount(1024)];     /* ditto */
    pthread_mutex_t vm_start_lock;      /* vm_start/vm_wait serialization lock */
    unsigned
        has_vm_start:1,                 /* protected by vm_start_lock */
        has_vm_wait:1;                  /* protected by vm_start_lock */
    pthread_mutex_t thread_lock;
    pthread_barrier_t barrier;
    pthread_t thread;                   /* protected by thread_lock */
    vm_count_t thread_count;
    vm_result_t thread_result;
    unsigned
        is_terminated:1,                /* protected by thread_lock */
        is_debuggable:1,                /* immutable */
        has_mmap_lock:1,                /* immutable */
        has_vm_start_lock:1,            /* immutable */
        has_thread_lock:1,              /* immutable */
        has_barrier:1,                  /* immutable */
        has_vm_debug_lock:1,            /* immutable */
        has_debug_server_lock:1,        /* immutable */
        has_thread:1;                   /* protected by thread_lock */
    pthread_mutex_t vm_debug_lock;      /* vm_debug serialization lock */
    struct vm_debug *debug;             /* protected by thread_lock */
    pthread_mutex_t debug_server_lock;
    struct vm_debug_server *debug_server; /* protected by debug_server_lock */
    struct
    {
        pthread_t thread;
        int has_thread;
        int vcpu_fd;
    } debug_thread_data[];              /* protected by thread_lock */
};

struct vm_mmap
{
    list_link_t mmap_link;              /* protected by mmap_lock */
    unsigned slot;
    uint8_t *region;
    uint64_t region_length;
    uint64_t guest_address;
    unsigned
        has_slot:1,
        has_region:1,
        has_mapped_region:1;
};

struct vm_debug
{
    vm_debug_events_t events;
    vm_debug_step_range_t step_range;
    pthread_cond_t stop_cvar, cont_cvar, wait_cvar;
        /* use condition variables for synchronization to streamline implementation across platforms */
    vm_count_t stop_cycle, stop_count, cont_cycle, cont_count;
    vm_count_t vcpu_index;
    vm_count_t bp_count;
    vm_count_t bp_ident[64];
    vm_count_t bp_paddr[64];
    uint32_t bp_value[64];
    unsigned
        is_debugged:1,
        is_stopped:1,
        is_continued:1,
        is_stepping:1,
        stop_on_start:1;
};

struct vm_debug_server
{
    pthread_t thread;                   /* protected by debug_server_lock; unsafe outside */
    union
    {
        int socket;                     /* safe outside debug_server_lock in vm_debug_server_thread */
        struct pollfd pollfd;           /* ditto */
    };
    int is_stopped;                     /* ditto */
    sigset_t sigset;                    /* ditto */
};

struct vm_debug_socket
{
    vm_t *instance;
    struct vm_debug_server *debug_server;
    union
    {
        int socket;
        struct pollfd pollfd;
    };
    pthread_mutex_t send_oob_lock;
    char send_oob_buffer[16];
    vm_count_t send_oob_length;
    unsigned
        has_send_oob_lock:1;
};

static vm_result_t vm_debug_internal(vm_t *instance,
    vm_count_t control, vm_count_t vcpu_index, vm_count_t address,
    void *buffer, vm_count_t *plength);
static int vm_debug_hasbp(vm_t *instance,
    vm_count_t vcpu_index, vm_count_t address);
static void *vm_thread(void *instance0);
static void vm_thread_signal(int signum);
static vm_result_t vm_thread_debug_event(vm_t *instance, unsigned vcpu_index, int vcpu_fd);
static vm_result_t vm_thread_debug_exit(vm_t *instance, unsigned vcpu_index, int vcpu_fd,
    struct kvm_run *vcpu_run, int *phas_debug_event);
static vm_result_t vm_vcpu_init(vm_t *instance, unsigned vcpu_index, int vcpu_fd);
static vm_result_t vm_vcpu_init_cpuid(vm_t *instance, unsigned vcpu_index, int vcpu_fd);
static vm_result_t vm_vcpu_debug(vm_t *instance, int vcpu_fd, int enable, int step, uint32_t inject);
static vm_result_t vm_vcpu_getregs(vm_t *instance, int vcpu_fd, void *buffer, vm_count_t *plength);
static vm_result_t vm_vcpu_setregs(vm_t *instance, int vcpu_fd, void *buffer, vm_count_t *plength);
static vm_result_t vm_vcpu_translate(vm_t *instance, int vcpu_fd,
    vm_count_t guest_virtual_address, vm_count_t *pguest_address);
static vm_result_t vm_default_xmio(void *user_context, vm_count_t vcpu_index,
    vm_count_t flags, vm_count_t address, vm_count_t length, void *buffer);
static void vm_log_mmap(vm_t *instance);
static void vm_log_vcpu_cancel(vm_t *instance,
    unsigned vcpu_index, vm_result_t result);
static void vm_log_vcpu_exit(vm_t *instance,
    unsigned vcpu_index, struct kvm_run *vcpu_run, vm_result_t result);
static int vm_debug_server_listen(struct addrinfo *info, int ai_family);
static void *vm_debug_server_thread(void *instance0);
static void vm_debug_server_thread_signal(int signum);
static vm_result_t vm_debug_server_strm(void *socket0, int dir, void *buffer, vm_count_t *plength);

/*
 * Register convenience macros
 *
 * Expected variables:
 *
 * - regn: register names (offsets within kvm_regs / kvm_sregs)
 * - regc: register count
 * - regb: register bit length (REGBIT only)
 * - regl: register total byte length (REGBIT only)
 */
#define REGNAM(r)                       regn[regc] = offsetof(struct kvm_regs, r), regc++
#define SREGNAM(r)                      regn[regc] = offsetof(struct kvm_sregs, r), regc++
#define REGBIT(b)                       regb[regc - 1] = (b), regl += regb[regc - 1] >> 3

VM_API
vm_result_t vm_create(const vm_config_t *config, vm_t **pinstance)
{
    struct sigaction action = { 0 };
    action.sa_handler = vm_thread_signal;
    sigaction(SIG_VCPU_CANCEL, &action, 0);
    action.sa_handler = vm_debug_server_thread_signal;
    sigaction(SIG_DBSRV_CANCEL, &action, 0);

    vm_result_t result;
    vm_t *instance = 0;
    vm_count_t vcpu_count;
    int error;

    *pinstance = 0;

    vcpu_count = config->vcpu_count;
    if (0 == vcpu_count)
    {
        cpu_set_t affinity;
        CPU_ZERO(&affinity);
        if (-1 == sched_getaffinity(0, sizeof affinity, &affinity))
        {
            result = vm_result(VM_ERROR_HYPERVISOR, errno);
            goto exit;
        }
        vcpu_count = (vm_count_t)CPU_COUNT(&affinity);
    }
    if (0 == vcpu_count)
        vcpu_count = 1;
    else if (VM_CONFIG_VCPU_COUNT_MAX < vcpu_count)
        vcpu_count = VM_CONFIG_VCPU_COUNT_MAX;

    instance = malloc(sizeof *instance + vcpu_count * sizeof instance->debug_thread_data[0]);
    if (0 == instance)
    {
        result = vm_result(VM_ERROR_RESOURCES, 0);
        goto exit;
    }

    memset(instance, 0, sizeof *instance);
    instance->config = *config;
    if (0 == instance->config.xmio)
        instance->config.xmio = vm_default_xmio;
    instance->config.vcpu_count = vcpu_count;
    instance->hv_fd = -1;
    instance->vm_fd = -1;
    list_init(&instance->mmap_list);
    for (vm_count_t index = 0; instance->config.vcpu_count > index; index++)
        instance->debug_thread_data[index].vcpu_fd = -1;

    error = pthread_mutex_init(&instance->mmap_lock, 0);
    if (0 != error)
    {
        result = vm_result(VM_ERROR_RESOURCES, error);
        goto exit;
    }
    instance->has_mmap_lock = 1;

    error = pthread_mutex_init(&instance->vm_start_lock, 0);
    if (0 != error)
    {
        result = vm_result(VM_ERROR_RESOURCES, error);
        goto exit;
    }
    instance->has_vm_start_lock = 1;

    error = pthread_mutex_init(&instance->thread_lock, 0);
    if (0 != error)
    {
        result = vm_result(VM_ERROR_RESOURCES, error);
        goto exit;
    }
    instance->has_thread_lock = 1;

    error = pthread_barrier_init(&instance->barrier, 0, 2);
    if (0 != error)
    {
        result = vm_result(VM_ERROR_RESOURCES, error);
        goto exit;
    }
    instance->has_barrier = 1;

    error = pthread_mutex_init(&instance->vm_debug_lock, 0);
    if (0 != error)
    {
        result = vm_result(VM_ERROR_RESOURCES, error);
        goto exit;
    }
    instance->has_vm_debug_lock = 1;

    error = pthread_mutex_init(&instance->debug_server_lock, 0);
    if (0 != error)
    {
        result = vm_result(VM_ERROR_RESOURCES, error);
        goto exit;
    }
    instance->has_debug_server_lock = 1;

    instance->hv_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (-1 == instance->hv_fd)
    {
        result = vm_result(VM_ERROR_HYPERVISOR, errno);
        goto exit;
    }

    if (12 != ioctl(instance->hv_fd, KVM_GET_API_VERSION, NULL))
    {
        result = vm_result(VM_ERROR_HYPERVISOR, 0);
        goto exit;
    }

    if (0 >= ioctl(instance->hv_fd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY) ||
        0 >= ioctl(instance->hv_fd, KVM_CHECK_EXTENSION, KVM_CAP_IMMEDIATE_EXIT))
    {
        result = vm_result(VM_ERROR_HYPERVISOR, 0);
        goto exit;
    }

    instance->vcpu_run_size = ioctl(instance->hv_fd, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (-1 == instance->vcpu_run_size)
    {
        result = vm_result(VM_ERROR_HYPERVISOR, errno);
        goto exit;
    }

    if (0 < ioctl(instance->hv_fd, KVM_CHECK_EXTENSION, KVM_CAP_SET_GUEST_DEBUG))
        instance->is_debuggable = 1;

    instance->vm_fd = ioctl(instance->hv_fd, KVM_CREATE_VM, NULL);
    if (-1 == instance->vm_fd)
    {
        result = vm_result(VM_ERROR_HYPERVISOR, errno);
        goto exit;
    }

    if (instance->config.passthrough || instance->config.vpic)
    {
        if (-1 == ioctl(instance->vm_fd, KVM_CREATE_IRQCHIP, NULL))
        {
            result = vm_result(VM_ERROR_HYPERVISOR, errno);
            goto exit;
        }

        struct kvm_pit_config pit_config = { 0 };
        if (-1 == ioctl(instance->vm_fd, KVM_CREATE_PIT2, &pit_config))
        {
            result = vm_result(VM_ERROR_HYPERVISOR, errno);
            goto exit;
        }
    }

    *pinstance = instance;
    result = VM_RESULT_SUCCESS;

exit:
    if (!vm_result_check(result) && 0 != instance)
        vm_delete(instance);

    return result;
}

VM_API
vm_result_t vm_delete(vm_t *instance)
{
    if (0 != instance->debug_server)
        vm_debug_server_stop(instance);

    if (0 != instance->debug)
    {
        pthread_cond_destroy(&instance->debug->wait_cvar);
        pthread_cond_destroy(&instance->debug->cont_cvar);
        pthread_cond_destroy(&instance->debug->stop_cvar);
    }

    while (!list_is_empty(&instance->mmap_list))
        vm_munmap(instance, (vm_mmap_t *)instance->mmap_list.next);

    if (-1 != instance->vm_fd)
        close(instance->vm_fd);

    if (-1 != instance->hv_fd)
        close(instance->hv_fd);

    if (instance->has_debug_server_lock)
        pthread_mutex_destroy(&instance->debug_server_lock);

    if (instance->has_vm_debug_lock)
        pthread_mutex_destroy(&instance->vm_debug_lock);

    if (instance->has_barrier)
        pthread_barrier_destroy(&instance->barrier);

    if (instance->has_thread_lock)
        pthread_mutex_destroy(&instance->thread_lock);

    if (instance->has_vm_start_lock)
        pthread_mutex_destroy(&instance->vm_start_lock);

    if (instance->has_mmap_lock)
        pthread_mutex_destroy(&instance->mmap_lock);

    free(instance->debug);
    free(instance);

    return VM_RESULT_SUCCESS;
}

VM_API
vm_result_t vm_mmap(vm_t *instance,
    vm_count_t guest_address, vm_count_t length,
    void *host_address, int file, vm_count_t file_offset, vm_count_t file_length,
    vm_mmap_t **pmap)
{
    vm_result_t result;
    vm_mmap_t *map = 0;
    size_t page_size;
    struct stat stbuf;
    vm_count_t file_end_offset, file_size;
    uint8_t *head;
    uint64_t head_length;
    struct kvm_userspace_memory_region region;

    *pmap = 0;

    page_size = (size_t)getpagesize();
    length = (length + page_size - 1) & ~(page_size - 1);

    if (0 != ((uintptr_t)host_address & (page_size - 1)) ||
        0 != (file_offset & (page_size - 1)) ||
        0 != (guest_address & (page_size - 1)) ||
        0 == length ||
        file_length > length)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    map = malloc(sizeof *map);
    if (0 == map)
    {
        result = vm_result(VM_ERROR_RESOURCES, 0);
        goto exit;
    }

    memset(map, 0, sizeof *map);
    list_init(&map->mmap_link);
        /* ensure that vm_munmap works even if we do not insert into the instance->mmap_list */

    map->guest_address = guest_address;

    pthread_mutex_lock(&instance->mmap_lock);
    map->slot = bmap_find(instance->slot_bmap, bmap_capacity(instance->slot_bmap), 0);
    if (map->slot < bmap_capacity(instance->slot_bmap))
    {
        map->has_slot = 1;
        bmap_set(instance->slot_bmap, map->slot, 1);
    }
    pthread_mutex_unlock(&instance->mmap_lock);
    if (!map->has_slot)
    {
        result = vm_result(VM_ERROR_MEMORY, 0);
        goto exit;
    }

    if (0 == host_address && -1 == file)
    {
        map->region_length = length;
        map->region = mmap(
            0, length, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (MAP_FAILED == map->region)
        {
            result = vm_result(VM_ERROR_MEMORY, errno);
            goto exit;
        }
        map->has_region = 1;
    }
    else if (0 == host_address && -1 != file)
    {
        if (-1 == fstat(file, &stbuf))
        {
            result = vm_result(VM_ERROR_FILE, errno);
            goto exit;
        }

        file_end_offset = file_offset + (0 != file_length ? file_length : length);
        file_size = (size_t)stbuf.st_size;
        if (file_end_offset > file_size)
            file_end_offset = file_size;

        head_length = file_end_offset - file_offset;
        head_length = (head_length + page_size - 1) & ~(page_size - 1);

        if (length > head_length)
        {
            map->region_length = length;
            map->region = mmap(
                0, length, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
            if (MAP_FAILED == map->region)
            {
                result = vm_result(VM_ERROR_MEMORY, errno);
                goto exit;
            }
            map->has_region = 1;

            head = mmap(
                map->region, file_end_offset - file_offset, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE,
                file, (off_t)file_offset);
            if (MAP_FAILED == head)
            {
                result = vm_result(VM_ERROR_MEMORY, errno);
                goto exit;
            }
        }
        else
        {
            map->region_length = length;
            map->region = mmap(
                0, file_end_offset - file_offset, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                file, (off_t)file_offset);
            if (MAP_FAILED == map->region)
            {
                result = vm_result(VM_ERROR_MEMORY, errno);
                goto exit;
            }
            map->has_region = 1;
        }
    }
    else if (0 != host_address && -1 == file)
    {
        map->region_length = length;
        map->region = host_address;
    }
    else if (0 != host_address && -1 != file)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    memset(&region, 0, sizeof region);
    region.slot = (__u32)map->slot;
    region.guest_phys_addr = map->guest_address;
    region.memory_size = map->region_length;
    region.userspace_addr = (__u64)map->region;
    if (-1 == ioctl(instance->vm_fd, KVM_SET_USER_MEMORY_REGION, &region))
    {
        result = vm_result(VM_ERROR_HYPERVISOR, errno);
        goto exit;
    }
    map->has_mapped_region = 1;

    pthread_mutex_lock(&instance->mmap_lock);
    list_insert_after(&instance->mmap_list, &map->mmap_link);
    pthread_mutex_unlock(&instance->mmap_lock);

    *pmap = map;
    result = VM_RESULT_SUCCESS;

exit:
    if (!vm_result_check(result) && 0 != map)
        vm_munmap(instance, map);

    return result;
}

VM_API
vm_result_t vm_munmap(vm_t *instance, vm_mmap_t *map)
{
    struct kvm_userspace_memory_region region;

    pthread_mutex_lock(&instance->mmap_lock);
    list_remove(&map->mmap_link);
    pthread_mutex_unlock(&instance->mmap_lock);

    if (map->has_mapped_region)
    {
        memset(&region, 0, sizeof region);
        region.slot = (__u32)map->slot;
        ioctl(instance->vm_fd, KVM_SET_USER_MEMORY_REGION, &region);
    }

    if (map->has_region)
        munmap(map->region, map->region_length);

    if (map->has_slot)
    {
        pthread_mutex_lock(&instance->mmap_lock);
        bmap_set(instance->slot_bmap, map->slot, 0);
        pthread_mutex_unlock(&instance->mmap_lock);
    }

    free(map);

    return VM_RESULT_SUCCESS;
}

VM_API
vm_result_t vm_mmap_read(vm_mmap_t *map,
    vm_count_t offset, void *buffer, vm_count_t *plength)
{
    vm_count_t length = 0;
    vm_count_t end_offset;

    if (offset >= map->region_length)
        goto exit;

    end_offset = offset + *plength;
    if (end_offset > map->region_length)
        end_offset = map->region_length;

    length = end_offset - offset;
    memcpy(buffer, map->region + offset, length);

exit:
    *plength = length;
    return VM_RESULT_SUCCESS;
}

VM_API
vm_result_t vm_mmap_write(vm_mmap_t *map,
    void *buffer, vm_count_t offset, vm_count_t *plength)
{
    vm_count_t length = 0;
    vm_count_t end_offset;

    if (offset >= map->region_length)
        goto exit;

    end_offset = offset + *plength;
    if (end_offset > map->region_length)
        end_offset = map->region_length;

    length = end_offset - offset;
    memcpy(map->region + offset, buffer, length);

exit:
    *plength = length;
    return VM_RESULT_SUCCESS;
}

VM_API
vm_result_t vm_mread(vm_t *instance,
    vm_count_t guest_address, void *buffer, vm_count_t *plength)
{
    vm_count_t length = 0;

    pthread_mutex_lock(&instance->mmap_lock);

    list_traverse(link, next, &instance->mmap_list)
    {
        vm_mmap_t *map = (vm_mmap_t *)link;
        if (map->guest_address <= guest_address &&
            guest_address < map->guest_address + map->region_length)
        {
            length = *plength;
            vm_mmap_read(map, guest_address - map->guest_address, buffer, &length);
            break;
        }
    }

    pthread_mutex_unlock(&instance->mmap_lock);

    *plength = length;
    return VM_RESULT_SUCCESS;
}

VM_API
vm_result_t vm_mwrite(vm_t *instance,
    void *buffer, vm_count_t guest_address, vm_count_t *plength)
{
    vm_count_t length = 0;

    pthread_mutex_lock(&instance->mmap_lock);

    list_traverse(link, next, &instance->mmap_list)
    {
        vm_mmap_t *map = (vm_mmap_t *)link;
        if (map->guest_address <= guest_address &&
            guest_address < map->guest_address + map->region_length)
        {
            length = *plength;
            vm_mmap_write(map, buffer, guest_address - map->guest_address, &length);
            break;
        }
    }

    pthread_mutex_unlock(&instance->mmap_lock);

    *plength = length;
    return VM_RESULT_SUCCESS;
}

VM_API
vm_result_t vm_reconfig(vm_t *instance, const vm_config_t *config, vm_count_t mask)
{
    vm_result_t result;

    if (0 != pthread_mutex_trylock(&instance->vm_start_lock))
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        return result;
    }

    if (instance->has_vm_start)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    mask &= VM_CONFIG_RECONFIG_MASK;
    for (vm_count_t index = 0; 0 != mask; mask >>= 1, index++)
        if (mask & 1)
            VM_CONFIG_FIELD(&instance->config, index) = VM_CONFIG_FIELD(config, index);

    result = VM_RESULT_SUCCESS;

exit:
    pthread_mutex_unlock(&instance->vm_start_lock);

    return result;
}

VM_API
vm_result_t vm_start(vm_t *instance)
{
    vm_result_t result;
    int error;

    if (0 != pthread_mutex_trylock(&instance->vm_start_lock))
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        return result;
    }

    if (instance->has_vm_start)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    if (instance->config.logf)
        vm_log_mmap(instance);

    pthread_mutex_lock(&instance->thread_lock);

    instance->thread_count = instance->config.vcpu_count;
    sigset_t newset, oldset;
    sigfillset(&newset);
    pthread_sigmask(SIG_SETMASK, &newset, &oldset);
    error = pthread_create(&instance->thread, 0, vm_thread, instance);
    pthread_sigmask(SIG_SETMASK, &oldset, 0);
        /* new thread has all signals blocked */
    result = 0 == error ?
        VM_RESULT_SUCCESS : vm_result(VM_ERROR_VCPU, error);
    if (vm_result_check(result))
        instance->has_vm_start = instance->has_thread = 1;

    pthread_mutex_unlock(&instance->thread_lock);

exit:
    pthread_mutex_unlock(&instance->vm_start_lock);

    return result;
}

VM_API
vm_result_t vm_wait(vm_t *instance)
{
    vm_result_t result;
    void *retval;

    pthread_mutex_lock(&instance->vm_start_lock);

    if (!instance->has_vm_start)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }
    if (instance->has_vm_wait)
        goto getres;

    pthread_barrier_wait(&instance->barrier);

    pthread_mutex_lock(&instance->thread_lock);

    pthread_join(instance->thread, &retval);
    instance->has_thread = 0;
    instance->has_vm_wait = 1;

    pthread_mutex_unlock(&instance->thread_lock);

getres:
    result = atomic_load(&instance->thread_result);
    if (VM_ERROR_TERMINATED == vm_result_error(result))
        result = VM_RESULT_SUCCESS;

exit:
    pthread_mutex_unlock(&instance->vm_start_lock);

    return result;
}

VM_API
vm_result_t vm_terminate(vm_t *instance)
{
    pthread_mutex_lock(&instance->thread_lock);

    instance->is_terminated = 1;
    if (instance->has_thread)
        pthread_kill(instance->thread, SIG_VCPU_CANCEL);
            /* if target already dead this fails with ESRCH; that's ok, we want to kill it anyway */
    if (0 != instance->debug)
    {
        pthread_cond_broadcast(&instance->debug->stop_cvar);
        pthread_cond_broadcast(&instance->debug->cont_cvar);
        pthread_cond_broadcast(&instance->debug->wait_cvar);
    }

    pthread_mutex_unlock(&instance->thread_lock);

    return VM_RESULT_SUCCESS;
}

VM_API
vm_result_t vm_debug(vm_t *instance,
    vm_count_t control, vm_count_t vcpu_index, vm_count_t address,
    void *buffer, vm_count_t *plength)
{
    vm_result_t result;

    pthread_mutex_lock(&instance->vm_debug_lock);
    pthread_mutex_lock(&instance->thread_lock);

    if (!instance->is_debuggable)
    {
        result = vm_result(VM_ERROR_HYPERVISOR, 0);
        goto exit;
    }

    if ((VM_DEBUG_ATTACH == control && 0 != instance->debug) ||
        (VM_DEBUG_ATTACH != control && 0 == instance->debug) ||
        instance->config.vcpu_count <= vcpu_index)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    result = vm_debug_internal(instance, control, vcpu_index, address, buffer, plength);

exit:
    pthread_mutex_unlock(&instance->thread_lock);
    pthread_mutex_unlock(&instance->vm_debug_lock);

    if (!vm_result_check(result) && 0 != plength)
        *plength = 0;

    return result;
}

static vm_result_t vm_debug_internal(vm_t *instance,
    vm_count_t control, vm_count_t vcpu_index, vm_count_t address,
    void *buffer, vm_count_t *plength)
{
    vm_result_t result;
    struct vm_debug *debug;
    int error;

    debug = instance->debug;

    switch (control)
    {
    case VM_DEBUG_ATTACH:
        if (instance->is_terminated)
        {
            result = vm_result(VM_ERROR_TERMINATED, 0);
            goto exit;
        }

        debug = malloc(sizeof *debug);
        if (0 == debug)
        {
            result = vm_result(VM_ERROR_RESOURCES, 0);
            goto exit;
        }

        memset(debug, 0, sizeof *debug);
        debug->is_debugged = 1;

        error = pthread_cond_init(&debug->stop_cvar, 0);
        if (0 != error)
        {
            free(debug);
            result = vm_result(VM_ERROR_RESOURCES, error);
            goto exit;
        }

        error = pthread_cond_init(&debug->cont_cvar, 0);
        if (0 != error)
        {
            pthread_cond_destroy(&debug->stop_cvar);
            free(debug);
            result = vm_result(VM_ERROR_RESOURCES, error);
            goto exit;
        }

        error = pthread_cond_init(&debug->wait_cvar, 0);
        if (0 != error)
        {
            pthread_cond_destroy(&debug->cont_cvar);
            pthread_cond_destroy(&debug->stop_cvar);
            free(debug);
            result = vm_result(VM_ERROR_RESOURCES, error);
            goto exit;
        }

        instance->debug = debug;
        break;

    case VM_DEBUG_DETACH:
        if (instance->is_terminated)
        {
            pthread_cond_destroy(&debug->wait_cvar);
            pthread_cond_destroy(&debug->cont_cvar);
            pthread_cond_destroy(&debug->stop_cvar);

            free(debug);
            instance->debug = 0;

            result = VM_RESULT_SUCCESS;
            goto exit;
        }
        if (!debug->is_stopped)
        {
            result = vm_result(VM_ERROR_MISUSE, 0);
            goto exit;
        }

        debug->events = (vm_debug_events_t){ 0 };

        for (vm_count_t index = debug->bp_count - 1; debug->bp_count > index; index--)
            vm_debug_internal(instance, VM_DEBUG_DELBP, ~0ULL, debug->bp_paddr[index], 0, 0);

        debug->is_debugged = 0;
        vm_debug_internal(instance, VM_DEBUG_CONT, 0, 0, 0, 0);

        pthread_cond_destroy(&debug->wait_cvar);
        pthread_cond_destroy(&debug->cont_cvar);
        pthread_cond_destroy(&debug->stop_cvar);

        free(debug);
        instance->debug = 0;
        break;

    case VM_DEBUG_SETEVENTS:
        if (instance->is_terminated)
        {
            result = vm_result(VM_ERROR_TERMINATED, 0);
            goto exit;
        }
        if (0 != plength && sizeof(vm_debug_events_t) > *plength)
        {
            result = vm_result(VM_ERROR_MISUSE, 0);
            goto exit;
        }

        if (0 != plength)
        {
            debug->events = *(vm_debug_events_t *)buffer;
            *plength = sizeof(vm_debug_events_t);
        }
        else
            debug->events = (vm_debug_events_t){ 0 };
        break;

    case VM_DEBUG_BREAK:
    case VM_DEBUG_WAIT:
        if (instance->is_terminated)
        {
            result = vm_result(VM_ERROR_TERMINATED, 0);
            goto exit;
        }
        if (debug->is_stopped)
            break;

        if (VM_DEBUG_BREAK == control)
            debug->stop_on_start = 1;
        if (instance->has_thread)
        {
            if (VM_DEBUG_BREAK == control)
            {
                for (unsigned index = 0; instance->config.vcpu_count > index; index++)
                    if (instance->debug_thread_data[index].has_thread)
                        pthread_kill(instance->debug_thread_data[index].thread, SIG_VCPU_CANCEL);
            }
            while (!instance->is_terminated &&
                !debug->is_stopped)
                pthread_cond_wait(&debug->stop_cvar, &instance->thread_lock);
        }
        break;

    case VM_DEBUG_CONT:
    case VM_DEBUG_STEP:
        if (instance->is_terminated)
        {
            result = vm_result(VM_ERROR_TERMINATED, 0);
            goto exit;
        }
        if (VM_DEBUG_STEP == control && 0 != plength && sizeof(vm_debug_step_range_t) > *plength)
        {
            result = vm_result(VM_ERROR_MISUSE, 0);
            goto exit;
        }
        if (!debug->is_stopped)
            break;

        debug->stop_on_start = 0;
        debug->is_stopped = 0;
        if (instance->has_thread)
        {
            debug->is_continued = 1;
            debug->vcpu_index = vcpu_index;
            debug->is_stepping = VM_DEBUG_STEP == control;
            debug->step_range = VM_DEBUG_STEP == control && 0 != plength ?
                *(vm_debug_step_range_t *)buffer :
                (vm_debug_step_range_t){ 0 };
            pthread_cond_broadcast(&debug->wait_cvar);
            while (!instance->is_terminated &&
                debug->is_continued)
                pthread_cond_wait(&debug->cont_cvar, &instance->thread_lock);
        }
        break;

    case VM_DEBUG_GETREGS:
    case VM_DEBUG_SETREGS:
        if (instance->is_terminated)
        {
            result = vm_result(VM_ERROR_TERMINATED, 0);
            goto exit;
        }
        if (!debug->is_stopped)
        {
            result = vm_result(VM_ERROR_MISUSE, 0);
            goto exit;
        }

        if (VM_DEBUG_GETREGS == control)
            result = vm_vcpu_getregs(instance,
                instance->debug_thread_data[vcpu_index].vcpu_fd, buffer, plength);
        else
            result = vm_vcpu_setregs(instance,
                instance->debug_thread_data[vcpu_index].vcpu_fd, buffer, plength);
        if (!vm_result_check(result))
            goto exit;
        break;

    case VM_DEBUG_GETVMEM:
    case VM_DEBUG_SETVMEM:
        if (instance->is_terminated)
        {
            result = vm_result(VM_ERROR_TERMINATED, 0);
            goto exit;
        }
        if (!debug->is_stopped)
        {
            result = vm_result(VM_ERROR_MISUSE, 0);
            goto exit;
        }

        {
            vm_count_t guest_address;
            vm_count_t length;

            length = *plength;
            *plength = 0;

            if (~0ULL != vcpu_index)
            {
                result = vm_vcpu_translate(instance,
                    instance->debug_thread_data[vcpu_index].vcpu_fd, address, &guest_address);
                if (!vm_result_check(result))
                    goto exit;
            }
            else
                guest_address = address;

            if (VM_DEBUG_GETVMEM == control)
                vm_mread(instance, guest_address, buffer, &length);
            else
                vm_mwrite(instance, buffer, guest_address, &length);

            *plength = length;
        }
        break;

    case VM_DEBUG_SETBP:
    case VM_DEBUG_DELBP:
        if (instance->is_terminated)
        {
            result = vm_result(VM_ERROR_TERMINATED, 0);
            goto exit;
        }
        if (!debug->is_stopped)
        {
            result = vm_result(VM_ERROR_MISUSE, 0);
            goto exit;
        }

        {
            vm_count_t bp_ident, bp_paddr, index;
            uint32_t bp_value = 0, bp_instr = VM_DEBUG_BP_INSTR;
            vm_count_t bp_length, bp_expected = VM_DEBUG_BP_LENGTH;

            bp_ident = bp_paddr = address;

            if (VM_DEBUG_SETBP == control && ~0ULL != vcpu_index)
            {
                result = vm_vcpu_translate(instance,
                    instance->debug_thread_data[vcpu_index].vcpu_fd, address, &bp_paddr);
                if (!vm_result_check(result))
                    goto exit;
            }

            if (~0ULL != vcpu_index)
            {
                for (index = 0; debug->bp_count > index; index++)
                    if (debug->bp_ident[index] == bp_ident)
                        break;
            }
            else
            {
                for (index = 0; debug->bp_count > index; index++)
                    if (debug->bp_paddr[index] == bp_paddr)
                        break;
            }

            if (debug->bp_count > index)
            {
                bp_ident = debug->bp_ident[index];
                bp_paddr = debug->bp_paddr[index];
            }

            /*
             * If we are setting a breakpoint and we already have one at the specified address
             * (debug->bp_count > index) then there is nothing to do and we can simply return.
             *
             * If we are deleting a breakpoint and we do not have one at the specified address
             * (debug->bp_count <= index) then there is nothing to do and we can simply return.
             */

            if (VM_DEBUG_SETBP == control && debug->bp_count <= index)
            {
                if (sizeof debug->bp_ident / sizeof debug->bp_ident[0] <= debug->bp_count)
                {
                    result = vm_result(VM_ERROR_MISUSE, 0);
                    goto exit;
                }

                bp_length = bp_expected;
                vm_mread(instance, bp_paddr, &bp_value, &bp_length);
                if (bp_length != bp_expected)
                {
                    result = vm_result(VM_ERROR_MEMORY, 0);
                    goto exit;
                }

                vm_mwrite(instance, &bp_instr, bp_paddr, &bp_length);
                if (bp_length != bp_expected)
                {
                    result = vm_result(VM_ERROR_MEMORY, 0);
                    goto exit;
                }

                debug->bp_ident[debug->bp_count] = bp_ident;
                debug->bp_paddr[debug->bp_count] = bp_paddr;
                debug->bp_value[debug->bp_count] = bp_value;
                debug->bp_count++;
            }
            else
            if (VM_DEBUG_DELBP == control && debug->bp_count > index)
            {
                bp_length = bp_expected;
                vm_mread(instance, bp_paddr, &bp_value, &bp_length);
                if (bp_length != bp_expected)
                {
                    result = vm_result(VM_ERROR_MEMORY, 0);
                    goto exit;
                }

                if (bp_value == bp_instr)
                {
                    /* only restore original value, if it still contains the breakpoint instruction */
                    vm_mwrite(instance, &debug->bp_value[index], bp_paddr, &bp_length);
                    if (bp_length != bp_expected)
                    {
                        result = vm_result(VM_ERROR_MEMORY, 0);
                        goto exit;
                    }
                }

                memmove(debug->bp_ident + index, debug->bp_ident + index + 1,
                    (debug->bp_count - index - 1) * sizeof debug->bp_ident[0]);
                memmove(debug->bp_paddr + index, debug->bp_paddr + index + 1,
                    (debug->bp_count - index - 1) * sizeof debug->bp_paddr[0]);
                memmove(debug->bp_value + index, debug->bp_value + index + 1,
                    (debug->bp_count - index - 1) * sizeof debug->bp_value[0]);
                debug->bp_count--;
            }
        }
        break;

    default:
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

static int vm_debug_hasbp(vm_t *instance,
    vm_count_t vcpu_index, vm_count_t address)
{
    vm_result_t result;
    vm_count_t bp_paddr, index;
    struct vm_debug *debug;

    debug = instance->debug;

    result = vm_vcpu_translate(instance,
        instance->debug_thread_data[vcpu_index].vcpu_fd, address, &bp_paddr);
    if (!vm_result_check(result))
        return 0;

    for (index = 0; debug->bp_count > index; index++)
        if (debug->bp_paddr[index] == bp_paddr)
            return 1;

    return 0;
}

static __thread struct kvm_run *vm_thread_vcpu_run;
static void *vm_thread(void *instance0)
{
    vm_result_t result;
    vm_t *instance = instance0;
    sigset_t newset, oldset;
    unsigned vcpu_index;
    int vcpu_fd = -1;
    struct kvm_run *vcpu_run = MAP_FAILED;
    pthread_t next_thread;
    int is_first_thread, has_next_thread;
    int is_terminated, has_debug_event, has_debug_log;
    int error;

    /* thread has all signals blocked -- see vm_start */

    sigfillset(&oldset);
    sigfillset(&newset);
    sigdelset(&newset, SIG_VCPU_CANCEL);

    vcpu_index = (unsigned)(instance->config.vcpu_count - instance->thread_count);
    is_first_thread = instance->config.vcpu_count == instance->thread_count;
    has_next_thread = 0;

    vcpu_fd = ioctl(instance->vm_fd, KVM_CREATE_VCPU, (void *)(uintptr_t)vcpu_index);
    if (-1 == vcpu_fd)
    {
        result = vm_result(VM_ERROR_VCPU, errno);
        goto exit;
    }

    vcpu_run = mmap(
        0, (size_t)instance->vcpu_run_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu_fd, 0);
    if (MAP_FAILED == vcpu_run)
    {
        result = vm_result(VM_ERROR_VCPU, errno);
        goto exit;
    }
    atomic_store_explicit(&vm_thread_vcpu_run, vcpu_run, memory_order_relaxed);

    pthread_mutex_lock(&instance->thread_lock);
    is_terminated = instance->is_terminated;
    has_debug_event = 0 != instance->debug && instance->debug->is_debugged &&
        instance->debug->stop_on_start;
    instance->debug_thread_data[vcpu_index].thread = pthread_self();
    instance->debug_thread_data[vcpu_index].has_thread = 1;
    instance->debug_thread_data[vcpu_index].vcpu_fd = vcpu_fd;
    pthread_mutex_unlock(&instance->thread_lock);
    if (is_terminated)
    {
        result = vm_result(VM_ERROR_TERMINATED, 0);
        goto exit;
    }

    /*
     * The following code block is thread-safe because the pthread_create call
     * ensures that we run in a lockstep fashion. This is because the call
     * must act as a barrier: by the time the new thread is created it must
     * observe the world as if all previous code has run.
     */
    if (1 < instance->thread_count)
    {
        instance->thread_count--;
        error = pthread_create(&next_thread, 0, vm_thread, instance);
        if (0 != error)
        {
            result = vm_result(VM_ERROR_VCPU, error);
            goto exit;
        }
        has_next_thread = 1;
    }

    result = vm_vcpu_init(instance, vcpu_index, vcpu_fd);
    if (!vm_result_check(result))
        goto exit;

    has_debug_log = !!instance->config.logf &&
        0 != (instance->config.log_flags & VM_CONFIG_LOG_HYPERVISOR);

    /* we are now able to accept cancellation signals */
    pthread_sigmask(SIG_SETMASK, &newset, 0);

    for (;;)
    {
        if (has_debug_event)
        {
            has_debug_event = 0;
            result = vm_thread_debug_event(instance, vcpu_index, vcpu_fd);
            if (!vm_result_check(result))
                goto exit;
        }

    restart:
        if (-1 == ioctl(vcpu_fd, KVM_RUN, NULL))
        {
            if (EINTR == errno)
            {
                __u8 expected = 1;
                if (!atomic_compare_exchange_strong_explicit(
                    &vcpu_run->immediate_exit, &expected, 0,
                    memory_order_relaxed, memory_order_relaxed))
                    goto restart;

                result = VM_RESULT_SUCCESS;
                has_debug_event = 0;
                pthread_mutex_lock(&instance->thread_lock);
                if (instance->is_terminated)
                    result = vm_result(VM_ERROR_TERMINATED, 0);
                else if (0 != instance->debug && instance->debug->is_debugged)
                    has_debug_event = 1;
                pthread_mutex_unlock(&instance->thread_lock);
                if (has_debug_log)
                    vm_log_vcpu_cancel(instance, vcpu_index, result);
                if (!vm_result_check(result))
                    goto exit;
                continue;
            }

            result = vm_result(VM_ERROR_VCPU, errno);
            goto exit;
        }

        switch (vcpu_run->exit_reason)
        {
        case KVM_EXIT_IO:
            for (__u32 index = 0; vcpu_run->io.count > index; index++)
            {
                result = instance->config.xmio(instance->config.user_context, vcpu_index,
                    VM_XMIO_PMIO | vcpu_run->io.direction, vcpu_run->io.port, vcpu_run->io.size,
                    (uint8_t *)vcpu_run + vcpu_run->io.data_offset);
                if (!vm_result_check(result))
                    break;
            }
            break;

        case KVM_EXIT_MMIO:
            result = instance->config.xmio(instance->config.user_context, vcpu_index,
                VM_XMIO_MMIO | vcpu_run->mmio.is_write, vcpu_run->mmio.phys_addr, vcpu_run->mmio.len,
                &vcpu_run->mmio.data);
            break;

        case KVM_EXIT_DEBUG:
            result = vm_thread_debug_exit(instance, vcpu_index, vcpu_fd, vcpu_run, &has_debug_event);
            break;

        case KVM_EXIT_HLT:
            result = vm_result(VM_ERROR_TERMINATED, 0);
            break;

        default:
            result = vm_result(VM_ERROR_VCPU, 0);
            break;
        }

        if (has_debug_log)
            vm_log_vcpu_exit(instance, vcpu_index, vcpu_run, result);
        if (!vm_result_check(result))
            goto exit;
    }

exit:
    /* we are no longer able to accept cancellation signals */
    pthread_sigmask(SIG_SETMASK, &oldset, 0);

    if (!vm_result_check(result))
    {
        vm_result_t expected = VM_RESULT_SUCCESS;
        atomic_compare_exchange_strong(&instance->thread_result, &expected, result);
    }

    pthread_mutex_lock(&instance->thread_lock);
    instance->is_terminated = 1;
    if (has_next_thread)
        pthread_kill(next_thread, SIG_VCPU_CANCEL);
    else if (!is_first_thread && instance->has_thread)
        pthread_kill(instance->thread, SIG_VCPU_CANCEL);
    if (0 != instance->debug)
    {
        pthread_cond_broadcast(&instance->debug->stop_cvar);
        pthread_cond_broadcast(&instance->debug->cont_cvar);
        pthread_cond_broadcast(&instance->debug->wait_cvar);
    }
    instance->debug_thread_data[vcpu_index].has_thread = 0;
    instance->debug_thread_data[vcpu_index].vcpu_fd = -1;
    pthread_mutex_unlock(&instance->thread_lock);

    if (has_next_thread)
    {
        void *retval;
        pthread_join(next_thread, &retval);
    }

    if (MAP_FAILED != vcpu_run)
    {
        atomic_store_explicit(&vm_thread_vcpu_run, 0, memory_order_relaxed);
        munmap(vcpu_run, (size_t)instance->vcpu_run_size);
    }

    if (-1 != vcpu_fd)
        close(vcpu_fd);

    if (is_first_thread)
        pthread_barrier_wait(&instance->barrier);

    return 0;
}

static void vm_thread_signal(int signum)
{
    /*
     * Pthread_getspecific and __thread are not async-signal safe.
     * However in practice they are.
     *
     * See https://stackoverflow.com/a/24653340/568557
     * See https://sourceware.org/legacy-ml/libc-alpha/2012-06/msg00372.html
     */

    struct kvm_run *vcpu_run = atomic_load_explicit(&vm_thread_vcpu_run, memory_order_relaxed);
    if (0 != vcpu_run)
        atomic_store_explicit(&vcpu_run->immediate_exit, 1, memory_order_relaxed);
}

static vm_result_t vm_thread_debug_event(vm_t *instance, unsigned vcpu_index, int vcpu_fd)
{
#define WAITCOND(cond, cvar)            \
    do                                  \
    {                                   \
        if (instance->is_terminated || 0 == (debug = instance->debug) || !debug->is_debugged)\
            goto skip_debug_event;      \
        if (cond)                       \
            break;                      \
        pthread_cond_wait(cvar, &instance->thread_lock);\
    } while (1)

    for (;;)
    {
        struct vm_debug *debug;
        int is_terminated = 0, is_debugged = 0, is_stepping = 0, other_is_stepping = 0;
        vm_count_t stop_cycle, cont_cycle;

        pthread_mutex_lock(&instance->thread_lock);

        if (instance->is_terminated || 0 == (debug = instance->debug) || !debug->is_debugged)
            goto skip_debug_event;

        /*
         * Interruptible barrier:
         *
         * - Terminate and debug detach events exit the barrier. Otherwise:
         * - All threads must stop and the is_stopped flag is set.
         */
        stop_cycle = debug->stop_cycle;
        if (instance->config.vcpu_count > ++debug->stop_count)
            WAITCOND(
                stop_cycle != debug->stop_cycle,
                &debug->stop_cvar);
        else
        {
            debug->stop_count = 0;
            debug->is_stopped = 1;
            if (0 != debug->events.handler)
                debug->events.handler(debug->events.self, instance, VM_DEBUG_BREAK, ~0ULL/*vcpu_index*/);
            debug->stop_cycle++;
            pthread_cond_broadcast(&debug->stop_cvar);
        }

        WAITCOND(
            debug->is_continued,
            &debug->wait_cvar);

        /*
         * Interruptible barrier:
         *
         * - Terminate and debug detach events exit the barrier. Otherwise:
         * - All threads must continue and the is_continued flag is cleared.
         */
        cont_cycle = debug->cont_cycle;
        if (instance->config.vcpu_count > ++debug->cont_count)
            WAITCOND(
                cont_cycle != debug->cont_cycle,
                &debug->cont_cvar);
        else
        {
            debug->cont_count = 0;
            debug->is_continued = 0;
            if (0 != debug->events.handler)
                debug->events.handler(debug->events.self, instance, VM_DEBUG_CONT, ~0ULL/*vcpu_index*/);
            debug->cont_cycle++;
            pthread_cond_broadcast(&debug->cont_cvar);
        }

        is_debugged = debug->is_debugged;
        is_stepping = is_debugged && debug->is_stepping && vcpu_index == debug->vcpu_index;
        other_is_stepping = is_debugged && debug->is_stepping && vcpu_index != debug->vcpu_index;

    skip_debug_event:
        is_terminated = instance->is_terminated;
        pthread_mutex_unlock(&instance->thread_lock);

        if (is_terminated)
            return vm_result(VM_ERROR_TERMINATED, 0);

        if (other_is_stepping)
            continue;

        return vm_vcpu_debug(instance, vcpu_fd, is_debugged, is_stepping, 0);
    }

#undef WAITCOND
}

static vm_result_t vm_thread_debug_exit(vm_t *instance, unsigned vcpu_index, int vcpu_fd,
    struct kvm_run *vcpu_run, int *phas_debug_event)
{
    vm_result_t result;
    struct vm_debug *debug;
    int has_debug_event, range_step;
    uint32_t inject;

    *phas_debug_event = 0;

#if defined(__x86_64__)
    vm_count_t pc = vcpu_run->debug.arch.pc;
    int is_db_ex = 1 == vcpu_run->debug.arch.exception;
    int is_bp_ex = 3 == vcpu_run->debug.arch.exception;
    if (!is_db_ex && !is_bp_ex)
#endif
    {
        result = vm_result(VM_ERROR_VCPU, 0);
        goto exit;
    }

    pthread_mutex_lock(&instance->thread_lock);

    has_debug_event = range_step = 0;
    inject = 0;
    if (is_db_ex)
    {
        if (0 != (debug = instance->debug) && debug->is_debugged &&
            debug->is_stepping)
        {
            range_step = debug->step_range.begin <= pc && pc < debug->step_range.end;
            has_debug_event = !range_step;
            debug->stop_on_start = 1;
        }
        else
            inject = KVM_GUESTDBG_INJECT_DB;
    }
    else if (is_bp_ex)
    {
        if (0 != (debug = instance->debug) && debug->is_debugged &&
            vm_debug_hasbp(instance, vcpu_index, pc))
        {
            for (unsigned index = 0; instance->config.vcpu_count > index; index++)
                if (index != vcpu_index && instance->debug_thread_data[index].has_thread)
                    pthread_kill(instance->debug_thread_data[index].thread, SIG_VCPU_CANCEL);
            has_debug_event = 1;
            debug->stop_on_start = 1;
        }
        else
            inject = KVM_GUESTDBG_INJECT_BP;
    }

    pthread_mutex_unlock(&instance->thread_lock);

    if (inject)
    {
        /*
         * If we are reinjecting do not report a debug event (has_debug_event == FALSE).
         */
        result = vm_vcpu_debug(instance, vcpu_fd, 1, 0, inject);
        if (!vm_result_check(result))
            goto exit;
    }
    else if (range_step)
    {
        /*
         * If we are range stepping do not report a debug event (has_debug_event == FALSE).
         * Instead prepare the virtual CPU for another single step through the step range.
         */
        result = vm_vcpu_debug(instance, vcpu_fd, 1, 1, 0);
        if (!vm_result_check(result))
            goto exit;
    }

    *phas_debug_event = has_debug_event;
    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

static vm_result_t vm_vcpu_init(vm_t *instance, unsigned vcpu_index, int vcpu_fd)
{
#if defined(__x86_64__)
    vm_result_t result;
    void *page = 0;
    vm_count_t vcpu_table, stride, length, cpu_data_address;
    vm_count_t vcpu_entry, vcpu_args[6];
    struct arch_x64_seg_desc seg_desc;
    struct arch_x64_sseg_desc sseg_desc;
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    struct kvm_mp_state mp_state;

    result = vm_vcpu_init_cpuid(instance, vcpu_index, vcpu_fd);
    if (!vm_result_check(result))
        goto exit;

    page = malloc(sizeof(struct arch_x64_cpu_data));
    if (0 == page)
    {
        result = vm_result(VM_ERROR_RESOURCES, 0);
        goto exit;
    }

    vcpu_table = instance->config.vcpu_table & ~0xff;
    stride = instance->config.vcpu_table & 0xff;
    cpu_data_address = vcpu_table + vcpu_index * stride * sizeof(struct arch_x64_cpu_data);
    arch_x64_cpu_data_init(page, cpu_data_address);
    length = sizeof(struct arch_x64_cpu_data);
    vm_mwrite(instance, page, cpu_data_address, &length);
    if (sizeof(struct arch_x64_cpu_data) != length)
    {
        result = vm_result(VM_ERROR_MEMORY, 0);
        goto exit;
    }

    if (0 == vcpu_index || 0 == instance->config.vcpu_mailbox)
    {
        vcpu_entry = instance->config.vcpu_entry;
        vcpu_args[0] = instance->config.vcpu_args[0];
        vcpu_args[1] = instance->config.vcpu_args[1];
        vcpu_args[2] = instance->config.vcpu_args[2];
        vcpu_args[3] = instance->config.vcpu_args[3];
        vcpu_args[4] = instance->config.vcpu_args[4];
        vcpu_args[5] = instance->config.vcpu_args[5];
    }
    else
    {
        vcpu_entry = (vm_count_t)&((struct arch_x64_cpu_data *)cpu_data_address)->wakeup.code;
        vcpu_args[0] = instance->config.vcpu_mailbox;
        vcpu_args[1] = ((vm_count_t)vcpu_index << 32) | 1;
        vcpu_args[2] = 0;
        vcpu_args[3] = 0;
        vcpu_args[4] = 0;
        vcpu_args[5] = 0;
    }

    memset(&regs, 0, sizeof regs);
    regs.rdi = vcpu_args[0];
    regs.rsi = vcpu_args[1];
    regs.rdx = vcpu_args[2];
    regs.rcx = vcpu_args[3];
    regs.r8 = vcpu_args[4];
    regs.r9 = vcpu_args[5];
    regs.rip = vcpu_entry;
    regs.rflags = 2;

    memset(&sregs, 0, sizeof sregs);
    seg_desc = ((struct arch_x64_cpu_data *)page)->gdt.km_cs;
    sregs.cs = (struct kvm_segment){
        .selector = (__u16)(uintptr_t)&((struct arch_x64_gdt *)0)->km_cs,
        .base = (__u64)(seg_desc.address0 | (seg_desc.address1 << 24)),
        .limit = (__u32)(seg_desc.limit0 | (seg_desc.limit1 << 16)),
        .type = seg_desc.type,
        .s = seg_desc.s,
        .dpl = seg_desc.dpl,
        .present = seg_desc.p,
        .avl = seg_desc.avl,
        .l = seg_desc.l,
        .db = seg_desc.db,
        .g = seg_desc.g };
    seg_desc = ((struct arch_x64_cpu_data *)page)->gdt.km_ds;
    sregs.ds = (struct kvm_segment){
        .selector = (__u16)(uintptr_t)&((struct arch_x64_gdt *)0)->km_ds,
        .base = (__u64)(seg_desc.address0 | (seg_desc.address1 << 24)),
        .limit = (__u32)(seg_desc.limit0 | (seg_desc.limit1 << 16)),
        .type = seg_desc.type,
        .s = seg_desc.s,
        .dpl = seg_desc.dpl,
        .present = seg_desc.p,
        .avl = seg_desc.avl,
        .l = seg_desc.l,
        .db = seg_desc.db,
        .g = seg_desc.g };
    sregs.es = (struct kvm_segment){
        .selector = (__u16)(uintptr_t)&((struct arch_x64_gdt *)0)->km_ds,
        .base = (__u64)(seg_desc.address0 | (seg_desc.address1 << 24)),
        .limit = (__u32)(seg_desc.limit0 | (seg_desc.limit1 << 16)),
        .type = seg_desc.type,
        .s = seg_desc.s,
        .dpl = seg_desc.dpl,
        .present = seg_desc.p,
        .avl = seg_desc.avl,
        .l = seg_desc.l,
        .db = seg_desc.db,
        .g = seg_desc.g };
    sregs.ss = (struct kvm_segment){
        .selector = (__u16)(uintptr_t)&((struct arch_x64_gdt *)0)->km_ds,
        .base = (__u64)(seg_desc.address0 | (seg_desc.address1 << 24)),
        .limit = (__u32)(seg_desc.limit0 | (seg_desc.limit1 << 16)),
        .type = seg_desc.type,
        .s = seg_desc.s,
        .dpl = seg_desc.dpl,
        .present = seg_desc.p,
        .avl = seg_desc.avl,
        .l = seg_desc.l,
        .db = seg_desc.db,
        .g = seg_desc.g };
    sseg_desc = ((struct arch_x64_cpu_data *)page)->gdt.tss;
    sregs.tr = (struct kvm_segment){
        .selector = (__u16)(uintptr_t)&((struct arch_x64_gdt *)0)->tss,
        .base = (__u64)((__u64)sseg_desc.address0 | ((__u64)sseg_desc.address1 << 24) |
            ((__u64)sseg_desc.address2 << 32)),
        .limit = (__u32)(sseg_desc.limit0 | (sseg_desc.limit1 << 16)),
        .type = 11,                     /* TYPE=11 (64-bit busy TSS) */
        .s = sseg_desc.s,
        .dpl = sseg_desc.dpl,
        .present = sseg_desc.p,
        .avl = sseg_desc.avl,
        .l = sseg_desc.l,
        .db = sseg_desc.db,
        .g = sseg_desc.g };
    sregs.gdt = (struct kvm_dtable){
        .base = cpu_data_address + (vm_count_t)&((struct arch_x64_cpu_data *)0)->gdt,
        .limit = sizeof(struct arch_x64_gdt) };
    sregs.idt = (struct kvm_dtable){
        .base = instance->config.vcpu_alt_table,
        .limit = 0 != instance->config.vcpu_alt_table ? sizeof(struct arch_x64_idt) : 0 };
    sregs.cr0 = 0x80000011;             /* PG=1,MP=1,PE=1 */
    sregs.cr3 = instance->config.page_table;
    sregs.cr4 = 0x00000020;             /* PAE=1 */
    sregs.efer = 0x00000500;            /* LMA=1,LME=1 */

    if (-1 == ioctl(vcpu_fd, KVM_SET_SREGS, &sregs))
    {
        result = vm_result(VM_ERROR_VCPU, errno);
        goto exit;
    }

    if (-1 == ioctl(vcpu_fd, KVM_SET_REGS, &regs))
    {
        result = vm_result(VM_ERROR_VCPU, errno);
        goto exit;
    }

    if (0 != vcpu_index && 0 != instance->config.vcpu_mailbox)
    {
        /* make sure that VCPU is runnable regardless if it is a boot or application one */
        mp_state.mp_state = KVM_MP_STATE_RUNNABLE;
        if (-1 == ioctl(vcpu_fd, KVM_SET_MP_STATE, &mp_state))
        {
            result = vm_result(VM_ERROR_VCPU, errno);
            goto exit;
        }
    }

    result = VM_RESULT_SUCCESS;

exit:
    free(page);

    return result;
#endif
}

static vm_result_t vm_vcpu_init_cpuid(vm_t *instance, unsigned vcpu_index, int vcpu_fd)
{
#if defined(__x86_64__)
    vm_result_t result;
    struct kvm_cpuid2 *cpuid_info = 0;
    const __u32 max_nent = 256;

    cpuid_info = malloc(sizeof *cpuid_info + max_nent * sizeof cpuid_info->entries[0]);
    if (0 == cpuid_info)
    {
        result = vm_result(VM_ERROR_RESOURCES, 0);
        goto exit;
    }

    cpuid_info->nent = max_nent;

    if (-1 == ioctl(instance->hv_fd, (int)KVM_GET_SUPPORTED_CPUID, cpuid_info))
    {
        result = vm_result(VM_ERROR_VCPU, errno);
        goto exit;
    }

    for (__u32 i = 0; cpuid_info->nent > i; i++)
        switch (cpuid_info->entries[i].function)
        {
        case 0x00000001:
            cpuid_info->entries[i].ebx = (vcpu_index << 24) |
                (cpuid_info->entries[i].ebx & 0x00ffffff);  /* fix LAPIC ID */
            cpuid_info->entries[i].ecx |= 0x80000000;       /* hypervisor present */
            break;
        case 0x40000000:
            if (!instance->config.passthrough)
            {
#define SIG_TO_REG(c0,c1,c2,c3)         ((c0) | ((c1) << 8) | ((c2) << 16) | ((c3) << 24))
                cpuid_info->entries[i].eax = 0x40000001;
                cpuid_info->entries[i].ebx = SIG_TO_REG('V','i','r','t');
                cpuid_info->entries[i].ecx = SIG_TO_REG('u','a','l','M');
                cpuid_info->entries[i].edx = SIG_TO_REG('e','t','a','l');
#undef SIG_TO_REG
            }
            break;
        case 0x40000001:
            if (!instance->config.passthrough)
            {
                cpuid_info->entries[i].eax = 0;
                cpuid_info->entries[i].ebx = 0;
                cpuid_info->entries[i].ecx = 0;
                cpuid_info->entries[i].edx = 0;
            }
            break;
        }

    if (-1 == ioctl(vcpu_fd, KVM_SET_CPUID2, cpuid_info))
    {
        result = vm_result(VM_ERROR_VCPU, errno);
        goto exit;
    }

    result = VM_RESULT_SUCCESS;

exit:
    free(cpuid_info);

    return result;
#endif
}

static vm_result_t vm_vcpu_debug(vm_t *instance, int vcpu_fd, int enable, int step, uint32_t inject)
{
    vm_result_t result;
    struct kvm_guest_debug debug;

    memset(&debug, 0, sizeof debug);
    if (enable)
        debug.control =
            KVM_GUESTDBG_ENABLE |
            KVM_GUESTDBG_USE_SW_BP |
            (step ? KVM_GUESTDBG_SINGLESTEP : 0) |
            inject;

    if (-1 == ioctl(vcpu_fd, KVM_SET_GUEST_DEBUG, &debug))
    {
        result = vm_result(VM_ERROR_VCPU, errno);
        goto exit;
    }

    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

static vm_result_t vm_vcpu_getregs(vm_t *instance, int vcpu_fd, void *buffer, vm_count_t *plength)
{
#if defined(__x86_64__)
    vm_result_t result;
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    uint16_t regn[128];
    uint8_t regb[128];
    unsigned regi, genc, regc, regl;
    uint64_t regv;
    uint8_t *bufp;
    vm_count_t length;

    length = *plength;
    *plength = 0;

    /* see gdb/features/i386/64bit-core.xml; we omit the floating point registers */
    regc = 0; regl = 0;
    REGNAM(rax); REGBIT(64);
    REGNAM(rbx); REGBIT(64);
    REGNAM(rcx); REGBIT(64);
    REGNAM(rdx); REGBIT(64);
    REGNAM(rsi); REGBIT(64);
    REGNAM(rdi); REGBIT(64);
    REGNAM(rbp); REGBIT(64);
    REGNAM(rsp); REGBIT(64);
    REGNAM(r8); REGBIT(64);
    REGNAM(r9); REGBIT(64);
    REGNAM(r10); REGBIT(64);
    REGNAM(r11); REGBIT(64);
    REGNAM(r12); REGBIT(64);
    REGNAM(r13); REGBIT(64);
    REGNAM(r14); REGBIT(64);
    REGNAM(r15); REGBIT(64);
    REGNAM(rip); REGBIT(64);
    REGNAM(rflags); REGBIT(32);
    genc = regc; /* general register count */
    SREGNAM(cs); REGBIT(32);
    SREGNAM(ss); REGBIT(32);
    SREGNAM(ds); REGBIT(32);
    SREGNAM(es); REGBIT(32);
    SREGNAM(fs); REGBIT(32);
    SREGNAM(gs); REGBIT(32);

    if (regl > length)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    if (-1 == ioctl(vcpu_fd, (int)KVM_GET_REGS, &regs))
    {
        result = vm_result(VM_ERROR_VCPU, errno);
        goto exit;
    }

    if (-1 == ioctl(vcpu_fd, (int)KVM_GET_SREGS, &sregs))
    {
        result = vm_result(VM_ERROR_VCPU, errno);
        goto exit;
    }

    bufp = buffer;
    for (regi = 0; genc > regi; regi++)
    {
        regv = *(uint64_t *)((uint8_t *)&regs + regn[regi]);
        switch (regb[regi])
        {
        case 64:
            bufp[7] = (uint8_t)(regv >> 56);
            bufp[6] = (uint8_t)(regv >> 48);
            bufp[5] = (uint8_t)(regv >> 40);
            bufp[4] = (uint8_t)(regv >> 32);
            /* fallthrough */
        case 32:
            bufp[3] = (uint8_t)(regv >> 24);
            bufp[2] = (uint8_t)(regv >> 16);
            bufp[1] = (uint8_t)(regv >> 8);
            bufp[0] = (uint8_t)(regv >> 0);
            break;
        }
        bufp += regb[regi] >> 3;
    }
    for (; regc > regi; regi++)
    {
        regv = *(uint16_t *)((uint8_t *)&sregs + regn[regi] + offsetof(struct kvm_segment, selector));
        bufp[3] = 0;
        bufp[2] = 0;
        bufp[1] = (uint8_t)(regv >> 8);
        bufp[0] = (uint8_t)(regv >> 0);
        bufp += regb[regi] >> 3;
    }

    *plength = regl;
    result = VM_RESULT_SUCCESS;

exit:
    return result;
#endif
}

static vm_result_t vm_vcpu_setregs(vm_t *instance, int vcpu_fd, void *buffer, vm_count_t *plength)
{
#if defined(__x86_64__)
    vm_result_t result;
    struct kvm_regs regs;
    uint16_t regn[128];
    uint8_t regb[128];
    unsigned regi, regc, regl;
    uint64_t regv;
    uint8_t *bufp;
    vm_count_t length;

    length = *plength;
    *plength = 0;

    /* see gdb/features/i386/64bit-core.xml; we omit the segment and floating point registers */
    regc = 0; regl = 0;
    REGNAM(rax); REGBIT(64);
    REGNAM(rbx); REGBIT(64);
    REGNAM(rcx); REGBIT(64);
    REGNAM(rdx); REGBIT(64);
    REGNAM(rsi); REGBIT(64);
    REGNAM(rdi); REGBIT(64);
    REGNAM(rbp); REGBIT(64);
    REGNAM(rsp); REGBIT(64);
    REGNAM(r8); REGBIT(64);
    REGNAM(r9); REGBIT(64);
    REGNAM(r10); REGBIT(64);
    REGNAM(r11); REGBIT(64);
    REGNAM(r12); REGBIT(64);
    REGNAM(r13); REGBIT(64);
    REGNAM(r14); REGBIT(64);
    REGNAM(r15); REGBIT(64);
    REGNAM(rip); REGBIT(64);
    REGNAM(rflags); REGBIT(32);

    if (regl > length)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    memset(&regs, 0, sizeof regs);

    bufp = buffer;
    for (regi = 0; regc > regi; regi++)
    {
        regv = 0;
        switch (regb[regi])
        {
        case 64:
            regv |= (uint64_t)bufp[7] << 56;
            regv |= (uint64_t)bufp[6] << 48;
            regv |= (uint64_t)bufp[5] << 40;
            regv |= (uint64_t)bufp[4] << 32;
            /* fallthrough */
        case 32:
            regv |= (uint64_t)bufp[3] << 24;
            regv |= (uint64_t)bufp[2] << 16;
            regv |= (uint64_t)bufp[1] << 8;
            regv |= (uint64_t)bufp[0] << 0;
            break;
        }
        *(uint64_t *)((uint8_t *)&regs + regn[regi]) = regv;
        bufp += regb[regi] >> 3;
    }

    if (-1 == ioctl(vcpu_fd, KVM_SET_REGS, &regs))
    {
        result = vm_result(VM_ERROR_VCPU, errno);
        goto exit;
    }

    *plength = regl;
    result = VM_RESULT_SUCCESS;

exit:
    return result;
#endif
}

static vm_result_t vm_vcpu_translate(vm_t *instance, int vcpu_fd,
    vm_count_t guest_virtual_address, vm_count_t *pguest_address)
{
    vm_result_t result;
    struct kvm_translation translation = { .linear_address = guest_virtual_address };

    *pguest_address = 0;

    if (-1 == ioctl(vcpu_fd, (int)KVM_TRANSLATE, &translation))
    {
        result = vm_result(VM_ERROR_VCPU, errno);
        goto exit;
    }
    if (!translation.valid)
    {
        result = vm_result(VM_ERROR_MEMORY, 0);
        goto exit;
    }

    *pguest_address = translation.physical_address;
    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

static vm_result_t vm_default_xmio(void *user_context, vm_count_t vcpu_index,
    vm_count_t flags, vm_count_t address, vm_count_t length, void *buffer)
{
    return vm_result(VM_ERROR_VCPU, 0);
}

static void vm_log_mmap(vm_t *instance)
{
    const size_t data_maxlen = 64 * 1024;
    char *data = 0;
    ssize_t bytes;
    int file;
    struct mmap_path
    {
        uint64_t address0, address1;
        char *path;
    } mmap_path[128];
    size_t mmap_path_count = 0;

    data = malloc(data_maxlen);
    if (0 == data)
        goto skip_maps;

    file = open("/proc/self/maps", O_RDONLY);
    if (-1 == file)
        goto skip_maps;

    bytes = pread(file, data, data_maxlen, 0);
    close(file);

    if (-1 == bytes)
        goto skip_maps;

    for (char *p = data, *endp = p + bytes;
        endp > p && sizeof mmap_path / sizeof mmap_path[0] > mmap_path_count;
        p++)
    {
        uint64_t address0 = 0, address1 = 0;
        char *path = 0;

        address0 = strtoullint(p, &p, +16);
        if ('-' == *p)
            address1 = strtoullint(p + 1, &p, +16);

        for (; endp > p && '\n' != *p; p++)
            if ('/' == *p)
                path = p + 1;
        if (endp > p && address0 < address1 && 0 != path)
        {
            *p = '\0';
            mmap_path[mmap_path_count].address0 = address0;
            mmap_path[mmap_path_count].address1 = address1;
            mmap_path[mmap_path_count].path = path;
            mmap_path_count++;
        }
    }

skip_maps:
    pthread_mutex_lock(&instance->mmap_lock);

    list_traverse(link, prev, &instance->mmap_list)
    {
        vm_mmap_t *map = (vm_mmap_t *)link;
        uint64_t end_address;
        char *path = 0;

        for (size_t i = 0; mmap_path_count > i; i++)
            if (mmap_path[i].address0 <= (uint64_t)map->region &&
                (uint64_t)map->region < mmap_path[i].address1)
            {
                path = mmap_path[i].path;
                break;
            }

        end_address = map->guest_address + map->region_length - 1;
        instance->config.logf("mmap %08x%08x-%08x%08x %7uK%s%s",
            (uint32_t)(map->guest_address >> 32), (uint32_t)map->guest_address,
            (uint32_t)(end_address >> 32), (uint32_t)end_address,
            (uint32_t)(map->region_length >> 10),
            path ? " " : "", path ? path : "");
    }

    pthread_mutex_unlock(&instance->mmap_lock);

    free(data);
}

static void vm_log_vcpu_cancel(vm_t *instance,
    unsigned vcpu_index, vm_result_t result)
{
    instance->config.logf("[%u] SIG_VCPU_CANCEL() = %s",
        vcpu_index,
        vm_result_error_string(result));
}

static void vm_log_vcpu_exit(vm_t *instance,
    unsigned vcpu_index, struct kvm_run *vcpu_run, vm_result_t result)
{
    switch (vcpu_run->exit_reason)
    {
    case KVM_EXIT_UNKNOWN:
        instance->config.logf("[%u] UNKNOWN(hardware_exit_reason=%llu) = %s",
            vcpu_index,
            (unsigned long long)vcpu_run->hw.hardware_exit_reason,
            vm_result_error_string(result));
        break;
    case KVM_EXIT_DEBUG:
        instance->config.logf("[%u] DEBUG() = %s",
            vcpu_index,
            vm_result_error_string(result));
        break;
    case KVM_EXIT_HLT:
        instance->config.logf("[%u] HLT() = %s",
            vcpu_index,
            vm_result_error_string(result));
        break;
    case KVM_EXIT_SHUTDOWN:
        instance->config.logf("[%u] SHUTDOWN() = %s",
            vcpu_index,
            vm_result_error_string(result));
        break;
    case KVM_EXIT_FAIL_ENTRY:
        instance->config.logf("[%u] FAIL_ENTRY(hardware_entry_failure_reason=0x%lx) = %s",
            vcpu_index,
            (unsigned long long)vcpu_run->fail_entry.hardware_entry_failure_reason,
            vm_result_error_string(result));
        break;
    case KVM_EXIT_INTERNAL_ERROR:
        instance->config.logf("[%u] INTERNAL_ERROR(suberror=%u) = %s",
            vcpu_index,
            (unsigned)vcpu_run->internal.suberror,
            vm_result_error_string(result));
        break;
    default:
        instance->config.logf("[%u] EXIT=%x() = %s",
            vcpu_index,
            vcpu_run->exit_reason,
            vm_result_error_string(result));
        break;
    }
}

VM_API
vm_result_t vm_debug_server_start(vm_t *instance,
    const char *hostname, const char *servname)
{
    vm_result_t result;
    int gai_err, error;
    struct addrinfo hint, *info = 0;
    struct vm_debug_server *debug_server = 0;

    pthread_mutex_lock(&instance->debug_server_lock);

    if (0 == servname || 0 != instance->debug_server)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    memset(&hint, 0, sizeof hint);
    hint.ai_flags = AI_PASSIVE;
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;
    gai_err = getaddrinfo(hostname, servname, &hint, &info);
    if (0 != gai_err)
    {
        result = vm_result(VM_ERROR_NETWORK, gai_err);
        goto exit;
    }

    debug_server = malloc(sizeof *debug_server);
    if (0 == debug_server)
    {
        result = vm_result(VM_ERROR_RESOURCES, 0);
        goto exit;
    }

    memset(debug_server, 0, sizeof *debug_server);
    debug_server->socket = -1;
    sigfillset(&debug_server->sigset);
    sigdelset(&debug_server->sigset, SIG_DBSRV_CANCEL);

    debug_server->socket = vm_debug_server_listen(info, AF_INET6);
    if (-1 == debug_server->socket)
        debug_server->socket = vm_debug_server_listen(info, AF_INET);
    if (-1 == debug_server->socket)
    {
        result = vm_result(VM_ERROR_NETWORK, errno);
        goto exit;
    }

    instance->debug_server = debug_server;

    sigset_t newset, oldset;
    sigfillset(&newset);
    pthread_sigmask(SIG_SETMASK, &newset, &oldset);
    error = pthread_create(&debug_server->thread, 0, vm_debug_server_thread, instance);
    pthread_sigmask(SIG_SETMASK, &oldset, 0);
        /* new thread has all signals blocked */
    result = 0 == error ?
        VM_RESULT_SUCCESS : vm_result(VM_ERROR_NETWORK, error);
    if (!vm_result_check(result))
    {
        instance->debug_server = 0;
        goto exit;
    }

    if (instance->config.logf)
        instance->config.logf("debug server listening on :%s", servname);

    result = VM_RESULT_SUCCESS;

exit:
    if (0 != info)
        freeaddrinfo(info);

    if (!vm_result_check(result) && 0 != debug_server)
    {
        if (-1 != debug_server->socket)
            close(debug_server->socket);
        free(debug_server);
    }

    pthread_mutex_unlock(&instance->debug_server_lock);

    return result;
}

VM_API
vm_result_t vm_debug_server_stop(vm_t *instance)
{
    vm_result_t result;
    void *retval;
    struct vm_debug_server *debug_server = 0;

    pthread_mutex_lock(&instance->debug_server_lock);

    if (0 == (debug_server = instance->debug_server))
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    atomic_store(&debug_server->is_stopped, 1);
    pthread_kill(debug_server->thread, SIG_DBSRV_CANCEL);

    pthread_join(debug_server->thread, &retval);
    if (-1 != debug_server->socket)
        close(debug_server->socket);
    free(debug_server);

    instance->debug_server = 0;

    result = VM_RESULT_SUCCESS;

exit:
    pthread_mutex_unlock(&instance->debug_server_lock);

    return result;
}

static int vm_debug_server_listen(struct addrinfo *info, int ai_family)
{
    int error = 0;
    for (struct addrinfo *p = info; p; p = p->ai_next)
        if (ai_family == p->ai_family)
        {
            int sock;
            int v6only = 0; /* dual stack socket */
            int reuse = 1;  /* reuse address */
            if (-1 == (sock = socket(p->ai_family, p->ai_socktype |
                    SOCK_NONBLOCK | SOCK_CLOEXEC, p->ai_protocol)) ||
                (AF_INET6 == p->ai_family && -1 == setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
                    &v6only, sizeof v6only)) ||
                -1 == setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                    &reuse, sizeof reuse) ||
                -1 == bind(sock, p->ai_addr, p->ai_addrlen) ||
                -1 == listen(sock, 1))
            {
                if (0 == error)
                    error = errno;
                if (-1 != sock)
                    close(sock);
                continue;
            }
            return sock;
        }
    errno = error;
    return -1;
}

static inline
int vm_debug_server_poll(struct vm_debug_server *debug_server, struct pollfd *pollfd, short events)
{
    if (atomic_load(&debug_server->is_stopped))
        return 0;
    pollfd->events = events;
    ppoll(pollfd, 1, 0, &debug_server->sigset);
    return !atomic_load(&debug_server->is_stopped);
}

static void *vm_debug_server_thread(void *instance0)
{
    vm_result_t result;
    vm_t *instance = instance0;
    struct vm_debug_socket debug_socket_buf, *debug_socket = &debug_socket_buf;
    struct vm_debug_server *debug_server;

    /* thread has all signals blocked -- see vm_debug_server_start */

    /*
     * It is safe to access instance->debug_server outside the debug_server_lock,
     * because our lifetime is controlled by debug_server_start / debug_server_stop
     * which do access instance->debug_server inside the debug_server_lock.
     */
    debug_server = instance->debug_server;

    while (vm_debug_server_poll(debug_server, &debug_server->pollfd, POLLIN))
    {
        memset(debug_socket, 0, sizeof *debug_socket);
        debug_socket->instance = instance;
        debug_socket->debug_server = debug_server;

        debug_socket->socket = accept4(debug_server->socket, 0, 0, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (-1 == debug_socket->socket)
        {
            switch (errno)
            {
            case EINTR:
            case EWOULDBLOCK:
                continue;
            case ENETDOWN:
            case EPROTO:
            case ENOPROTOOPT:
            case EHOSTDOWN:
            case ENONET:
            case EHOSTUNREACH:
            case EOPNOTSUPP:
            case ENETUNREACH:
            case ECONNABORTED:
                /* retry on transient errors as per accept4 man page */
                continue;
            }
            result = vm_result(VM_ERROR_NETWORK, errno);
            goto exit;
        }

        result = VM_RESULT_SUCCESS;

        if (0 != pthread_mutex_init(&debug_socket->send_oob_lock, 0))
            goto loop_bottom;
        debug_socket->has_send_oob_lock = 1;
        debug_socket->send_oob_length = 0;

        int nodelay = 1;
        setsockopt(debug_socket->socket, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof nodelay);

        result = vm_gdb(instance, vm_debug_server_strm, debug_socket);

    loop_bottom:
        close(debug_socket->socket);

        if (debug_socket->has_send_oob_lock)
            pthread_mutex_destroy(&debug_socket->send_oob_lock);

        if (VM_ERROR_TERMINATED == vm_result_error(result))
            break;
    }

exit:
    (void)result;
    return 0;
}

static void vm_debug_server_thread_signal(int signum)
{
}

static vm_result_t vm_debug_server_strm(void *socket0, int dir, void *buffer, vm_count_t *plength)
{
    vm_result_t result;
    struct vm_debug_socket *debug_socket = (struct vm_debug_socket *)socket0;
    struct vm_debug_server *debug_server = debug_socket->debug_server;
    size_t length;
    ssize_t tbytes, bytes;

    length = (size_t)*plength;
    tbytes = 0;
    *plength = 0;

    if (-2 == dir)
    {
        if (sizeof debug_socket->send_oob_buffer < length)
            return vm_result(VM_ERROR_MISUSE, 0);

        pthread_mutex_lock(&debug_socket->send_oob_lock);
        memcpy(debug_socket->send_oob_buffer, buffer,
            debug_socket->send_oob_length = length);
        pthread_mutex_unlock(&debug_socket->send_oob_lock);

        /* signal the stop event without setting is_stopped */
        pthread_kill(debug_server->thread, SIG_DBSRV_CANCEL);

        *plength = length;
        return VM_RESULT_SUCCESS;
    }

    if (+1 != dir && -1 != dir)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    for (;;)
    {
        if (+1 == dir)
        {
            char send_oob_buffer[sizeof debug_socket->send_oob_buffer];
            vm_count_t send_oob_length;
            pthread_mutex_lock(&debug_socket->send_oob_lock);
            memcpy(send_oob_buffer, debug_socket->send_oob_buffer,
                send_oob_length = debug_socket->send_oob_length);
            debug_socket->send_oob_length = 0;
            pthread_mutex_unlock(&debug_socket->send_oob_lock);
            if (0 < send_oob_length)
                vm_debug_server_strm(socket0, -1, send_oob_buffer, &send_oob_length);

            bytes = recv(debug_socket->socket, buffer, length, 0);
            if (0 <= bytes)
            {
                if (debug_socket->instance->config.logf &&
                    0 != (debug_socket->instance->config.log_flags & VM_CONFIG_LOG_DEBUGSERVER))
                    debug_socket->instance->config.logf("RECV: %.*s", 512 > bytes ? (int)bytes : 512, buffer);
                tbytes += bytes;
                break;
            }
        }
        else
        {
            bytes = send(debug_socket->socket, buffer, length, MSG_NOSIGNAL);
            if (0 <= bytes)
            {
                if (debug_socket->instance->config.logf &&
                    0 != (debug_socket->instance->config.log_flags & VM_CONFIG_LOG_DEBUGSERVER))
                    debug_socket->instance->config.logf("SEND: %.*s", 512 > bytes ? (int)bytes : 512, buffer);
                tbytes += bytes;
                buffer = (char *)buffer + bytes;
                length -= (size_t)bytes;
                if (0 < length)
                    continue;
                else
                    break;
            }
        }

        if (EWOULDBLOCK == errno)
        {
            if (!vm_debug_server_poll(debug_server,
                &debug_socket->pollfd, +1 == dir ? POLLIN : POLLOUT))
            {
                result = vm_result(VM_ERROR_TERMINATED, 0);
                goto exit;
            }
            continue;
        }

        result = vm_result(VM_ERROR_NETWORK, errno);
        goto exit;
    }

    *plength = (vm_count_t)tbytes;
    result = VM_RESULT_SUCCESS;

exit:
    return result;
}
