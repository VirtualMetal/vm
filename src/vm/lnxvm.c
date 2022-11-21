/**
 * @file vm/lnxvm.c
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

#define SIG_VCPU_CANCEL                 SIGUSR1

struct vm
{
    vm_config_t config;
    int hv_fd;
    int vm_fd;
    int vcpu_run_size;
    pthread_mutex_t mmap_lock;
    list_link_t mmap_list;              /* protected by mmap_lock */
    bmap_t slot_bmap[bmap_declcount(1024)];     /* ditto */
    pthread_mutex_t thread_lock;
    pthread_barrier_t barrier;
    pthread_t thread;                   /* protected by thread_lock */
    vm_count_t thread_count;
    vm_result_t thread_result;
    unsigned
        is_terminated:1,                /* protected by thread_lock */
        is_debuggable:1,                /* immutable */
        has_mmap_lock:1,                /* immutable */
        has_thread_lock:1,              /* immutable */
        has_barrier:1,                  /* immutable */
        has_vm_debug_lock:1,            /* immutable */
        has_start_debug_event:1,        /* protected by thread_lock */
        has_thread:1;                   /* protected by thread_lock */
    struct vm_debug *debug;             /* protected by thread_lock */
    pthread_mutex_t vm_debug_lock;      /* vm_debug serialization lock */
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
    pthread_cond_t stop_cvar, cont_cvar, wait_cvar;
        /* use condition variables for synchronization to streamline implementation across platforms */
    vm_count_t stop_count, cont_count;
    vm_count_t vcpu_index;
    vm_count_t bp_count;
    vm_count_t bp_address[64];
    uint32_t bp_value[64];
    unsigned
        is_debugged:1,
        is_stopped:1,
        is_continued:1,
        single_step:1;
    struct
    {
        pthread_t thread;
        int has_thread;
        int vcpu_fd;
    } thread_data[];
};

static vm_result_t vm_debug_internal(vm_t *instance, vm_count_t control, vm_count_t vcpu_index,
    void *buffer, vm_count_t *plength);
static void *vm_thread(void *instance0);
static void vm_thread_signal(int signum);
static vm_result_t vm_thread_debug_event(vm_t *instance, unsigned vcpu_index, int vcpu_fd);
static vm_result_t vm_vcpu_init(vm_t *instance, unsigned vcpu_index, int vcpu_fd);
static vm_result_t vm_vcpu_debug(vm_t *instance, int vcpu_fd, int enable, int step);
static vm_result_t vm_vcpu_getregs(vm_t *instance, int vcpu_fd, void *buffer, vm_count_t *plength);
static vm_result_t vm_vcpu_setregs(vm_t *instance, int vcpu_fd, void *buffer, vm_count_t *plength);
static void vm_debug_log_mmap(vm_t *instance);
static void vm_debug_log_cancel(vm_t *instance,
    unsigned vcpu_index, vm_result_t result);
static void vm_debug_log_exit(vm_t *instance,
    unsigned vcpu_index, struct kvm_run *vcpu_run, vm_result_t result);

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
#define REGBIT(b)                       regb[regc - 1] = (b), regl += regb[regc - 1]

vm_result_t vm_create(const vm_config_t *config, vm_t **pinstance)
{
    vm_result_t result;
    vm_t *instance = 0;
    int error;

    *pinstance = 0;

    instance = malloc(sizeof *instance);
    if (0 == instance)
    {
        result = vm_result(VM_ERROR_RESOURCES, 0);
        goto exit;
    }

    memset(instance, 0, sizeof *instance);
    instance->config = *config;
    instance->hv_fd = -1;
    instance->vm_fd = -1;
    list_init(&instance->mmap_list);

    if (0 == instance->config.vcpu_count)
    {
        cpu_set_t affinity;
        CPU_ZERO(&affinity);
        if (-1 == sched_getaffinity(0, sizeof affinity, &affinity))
        {
            result = vm_result(VM_ERROR_HYPERVISOR, errno);
            goto exit;
        }
        instance->config.vcpu_count = (vm_count_t)CPU_COUNT(&affinity);
    }
    if (0 == instance->config.vcpu_count)
        instance->config.vcpu_count = 1;

    error = pthread_mutex_init(&instance->mmap_lock, 0);
    if (0 != error)
    {
        result = vm_result(VM_ERROR_RESOURCES, error);
        goto exit;
    }
    instance->has_mmap_lock = 1;

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

    *pinstance = instance;
    result = VM_RESULT_SUCCESS;

exit:
    if (!vm_result_check(result) && 0 != instance)
        vm_delete(instance);

    return result;
}

vm_result_t vm_delete(vm_t *instance)
{
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

    if (instance->has_vm_debug_lock)
        pthread_mutex_destroy(&instance->vm_debug_lock);

    if (instance->has_barrier)
        pthread_barrier_destroy(&instance->barrier);

    if (instance->has_thread_lock)
        pthread_mutex_destroy(&instance->thread_lock);

    if (instance->has_mmap_lock)
        pthread_mutex_destroy(&instance->mmap_lock);

    free(instance->debug);
    free(instance);

    return VM_RESULT_SUCCESS;
}

vm_result_t vm_mmap(vm_t *instance,
    void *host_address, int file, vm_count_t guest_address, vm_count_t length,
    vm_mmap_t **pmap)
{
    vm_result_t result;
    vm_mmap_t *map = 0;
    size_t page_size;
    struct stat stbuf;
    uint8_t *head;
    uint64_t head_length;
    struct kvm_userspace_memory_region region;

    *pmap = 0;

    page_size = (size_t)getpagesize();
    length = (length + page_size - 1) & ~(page_size - 1);

    if (0 != ((uintptr_t)host_address & (page_size - 1)) ||
        0 != (guest_address & (page_size - 1)) ||
        0 == length)
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

        map->region_length = length;
        map->region = mmap(
            0, length, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (MAP_FAILED == map->region)
        {
            result = vm_result(VM_ERROR_MEMORY, errno);
            goto exit;
        }
        map->has_region = 1;

        head_length = ((size_t)stbuf.st_size + page_size - 1) & ~(page_size - 1);
        if (head_length > length)
            head_length = length;

        head = mmap(
            map->region, head_length, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE, file, 0);
        if (MAP_FAILED == head)
        {
            result = vm_result(VM_ERROR_MEMORY, errno);
            goto exit;
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

vm_result_t vm_start(vm_t *instance)
{
    vm_result_t result;
    int error;

    if (instance->has_thread)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    if (instance->config.debug_log)
        vm_debug_log_mmap(instance);

    atomic_store(&instance->thread_result, VM_RESULT_SUCCESS);

    pthread_mutex_lock(&instance->thread_lock);

    if (!instance->is_terminated)
    {
        instance->has_start_debug_event = 0 != instance->debug && instance->debug->is_debugged;
        instance->thread_count = instance->config.vcpu_count;

        sigset_t newset, oldset;
        sigfillset(&newset);
        pthread_sigmask(SIG_SETMASK, &newset, &oldset);
        error = pthread_create(&instance->thread, 0, vm_thread, instance);
        pthread_sigmask(SIG_SETMASK, &oldset, 0);
            /* new thread has all signals blocked */

        if (0 != error)
            result = vm_result(VM_ERROR_VCPU, error);
        else
            instance->has_thread = 1;
    }
    else
    {
        error = EINTR; /* ignored */
        result = vm_result(VM_ERROR_TERMINATED, 0);
    }

    pthread_mutex_unlock(&instance->thread_lock);

    if (0 != error)
        goto exit;

    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

vm_result_t vm_wait(vm_t *instance)
{
    vm_result_t result;
    void *retval;

    if (!instance->has_thread)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    pthread_barrier_wait(&instance->barrier);

    pthread_mutex_lock(&instance->thread_lock);

    pthread_join(instance->thread, &retval);
    instance->has_thread = 0;

    pthread_mutex_unlock(&instance->thread_lock);

    result = atomic_load(&instance->thread_result);
    if (VM_ERROR_TERMINATED == vm_result_error(result))
        result = VM_RESULT_SUCCESS;

exit:
    return result;
}

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

vm_result_t vm_debug(vm_t *instance, vm_count_t control, vm_count_t vcpu_index,
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

    result = vm_debug_internal(instance, control, vcpu_index, buffer, plength);

exit:
    pthread_mutex_unlock(&instance->thread_lock);
    pthread_mutex_unlock(&instance->vm_debug_lock);

    if (!vm_result_check(result) && 0 != plength)
        *plength = 0;

    return result;
}

static vm_result_t vm_debug_internal(vm_t *instance, vm_count_t control, vm_count_t vcpu_index,
    void *buffer, vm_count_t *plength)
{
    vm_result_t result;
    struct vm_debug *debug;
    int error;

    debug = instance->debug;

    switch (control)
    {
    case VM_DEBUG_ATTACH:
        if (0 != plength && sizeof(vm_debug_events_t) > *plength)
        {
            result = vm_result(VM_ERROR_MISUSE, 0);
            goto exit;
        }

        debug = malloc(sizeof *debug + instance->config.vcpu_count * sizeof debug->thread_data[0]);
        if (0 == debug)
        {
            result = vm_result(VM_ERROR_RESOURCES, 0);
            goto exit;
        }

        memset(debug, 0, sizeof *debug);
        if (0 != plength)
        {
            debug->events = *(vm_debug_events_t *)buffer;
            *plength = sizeof(vm_debug_events_t);
        }
        debug->cont_count = instance->config.vcpu_count;
        debug->is_debugged = 1;
        for (vm_count_t index = 0; instance->config.vcpu_count > index; index++)
            debug->thread_data[index].vcpu_fd = -1;

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
        if (!debug->is_stopped)
        {
            result = vm_result(VM_ERROR_MISUSE, 0);
            goto exit;
        }

        for (vm_count_t index = debug->bp_count - 1; debug->bp_count > index; index--)
        {
            vm_count_t length = sizeof debug->bp_address[index];
            vm_debug_internal(instance, VM_DEBUG_DELBP, 0, &debug->bp_address[index], &length);
        }

        debug->is_debugged = 0;
        vm_debug_internal(instance, VM_DEBUG_CONT, 0, 0, 0);

        pthread_cond_destroy(&debug->wait_cvar);
        pthread_cond_destroy(&debug->cont_cvar);
        pthread_cond_destroy(&debug->stop_cvar);

        free(debug);

        instance->debug = 0;
        break;

    case VM_DEBUG_BREAK:
        if (debug->is_stopped)
            break;

        if (instance->has_thread)
        {
            for (unsigned index = 0; instance->config.vcpu_count > index; index++)
                if (debug->thread_data[index].has_thread)
                    pthread_kill(debug->thread_data[index].thread, SIG_VCPU_CANCEL);
            while (!instance->is_terminated &&
                !debug->is_stopped)
                pthread_cond_wait(&debug->stop_cvar, &instance->thread_lock);
            if (instance->is_terminated)
            {
                result = vm_result(VM_ERROR_TERMINATED, 0);
                goto exit;
            }
        }
        break;

    case VM_DEBUG_CONT:
    case VM_DEBUG_STEP:
        if (!debug->is_stopped)
            break;

        debug->is_stopped = 0;
        if (instance->has_thread)
        {
            debug->is_continued = 1;
            debug->vcpu_index = vcpu_index;
            debug->single_step = VM_DEBUG_STEP == control;
            pthread_cond_broadcast(&debug->wait_cvar);
            while (!instance->is_terminated &&
                debug->is_continued)
                pthread_cond_wait(&debug->cont_cvar, &instance->thread_lock);
            if (instance->is_terminated)
            {
                result = vm_result(VM_ERROR_TERMINATED, 0);
                goto exit;
            }
        }
        break;

    case VM_DEBUG_GETREGS:
    case VM_DEBUG_SETREGS:
        if (!debug->is_stopped)
        {
            result = vm_result(VM_ERROR_MISUSE, 0);
            goto exit;
        }

        if (VM_DEBUG_GETREGS == control)
            result = vm_vcpu_getregs(instance, debug->thread_data[vcpu_index].vcpu_fd, buffer, plength);
        else
            result = vm_vcpu_setregs(instance, debug->thread_data[vcpu_index].vcpu_fd, buffer, plength);
        if (!vm_result_check(result))
            goto exit;
        break;

    case VM_DEBUG_SETBP:
    case VM_DEBUG_DELBP:
        if (!debug->is_stopped || sizeof(vm_count_t) > *plength)
        {
            result = vm_result(VM_ERROR_MISUSE, 0);
            goto exit;
        }

        {
            vm_count_t bp_address = *(vm_count_t *)buffer;
            vm_count_t index;
#if defined(__x86_64__)
            uint32_t bp_value, bp_instr = 0xcc/* INT3 instruction */;
            vm_count_t bp_length, bp_expected = 1;
#endif

            *plength = sizeof(vm_count_t);

            for (index = 0; debug->bp_count > index; index++)
                if (debug->bp_address[index] == bp_address)
                    break;

            if (VM_DEBUG_SETBP == control && debug->bp_count <= index)
            {
                if (sizeof debug->bp_address / sizeof debug->bp_address[0] >
                    debug->bp_count)
                {
                    result = vm_result(VM_ERROR_MISUSE, 0);
                    goto exit;
                }

                bp_length = bp_expected;
                vm_mread(instance, bp_address, &bp_value, &bp_length);
                if (bp_length != bp_expected)
                {
                    result = vm_result(VM_ERROR_MEMORY, 0);
                    goto exit;
                }

                vm_mwrite(instance, &bp_instr, bp_address, &bp_length);
                if (bp_length != bp_expected)
                {
                    result = vm_result(VM_ERROR_MEMORY, 0);
                    goto exit;
                }

                debug->bp_address[debug->bp_count] = bp_address;
                debug->bp_value[debug->bp_count] = 0;
                debug->bp_count++;
            }
            else
            if (VM_DEBUG_DELBP == control && debug->bp_count > index)
            {
                bp_length = bp_expected;
                vm_mread(instance, bp_address, &bp_value, &bp_length);
                if (bp_length != bp_expected)
                {
                    result = vm_result(VM_ERROR_MEMORY, 0);
                    goto exit;
                }

                if (bp_value == bp_instr)
                {
                    /* only restore original value, if it still contains the breakpoint instruction */
                    vm_mwrite(instance, &debug->bp_value[index], bp_address, &bp_length);
                    if (bp_length != bp_expected)
                    {
                        result = vm_result(VM_ERROR_MEMORY, 0);
                        goto exit;
                    }
                }

                memmove(debug->bp_address + index, debug->bp_address + index + 1,
                    (debug->bp_count - index - 1) * sizeof debug->bp_address[0]);
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

static __thread struct kvm_run *vm_thread_vcpu_run;
static void *vm_thread(void *instance0)
{
    vm_result_t result;
    vm_t *instance = instance0;
    unsigned vcpu_index;
    int vcpu_fd = -1;
    struct kvm_run *vcpu_run = MAP_FAILED;
    pthread_t next_thread;
    int is_first_thread, has_next_thread;
    int is_terminated, has_debug_event, has_debug_log;
    struct sigaction action;
    sigset_t sigset;
    int error;

    /* thread has all signals blocked -- see vm_start */

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
    has_debug_event = instance->has_start_debug_event;
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

    has_debug_log = !!instance->config.debug_log;

    /* we are now ready to accept cancel signal */

    memset(&action, 0, sizeof action);
    action.sa_handler = vm_thread_signal;
    sigaction(SIG_VCPU_CANCEL, &action, 0);

    sigemptyset(&sigset);
    sigaddset(&sigset, SIG_VCPU_CANCEL);
    pthread_sigmask(SIG_UNBLOCK, &sigset, 0);

    for (;;)
    {
        if (has_debug_event)
        {
            has_debug_event = 0;
            result = vm_thread_debug_event(instance, vcpu_index, vcpu_fd);
            if (!vm_result_check(result))
                goto exit;
        }

        if (-1 == ioctl(vcpu_fd, KVM_RUN, NULL))
        {
            if (EINTR == errno)
            {
                result = VM_RESULT_SUCCESS;
                has_debug_event = 0;
                pthread_mutex_lock(&instance->thread_lock);
                if (instance->is_terminated)
                    result = vm_result(VM_ERROR_TERMINATED, 0);
                else if (0 != instance->debug && instance->debug->is_debugged)
                    has_debug_event = 1;
                pthread_mutex_unlock(&instance->thread_lock);
                if (has_debug_log)
                    vm_debug_log_cancel(instance, vcpu_index, result);
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
            result = vm_result(VM_ERROR_VCPU, 0);
            break;

        case KVM_EXIT_MMIO:
            result = vm_result(VM_ERROR_VCPU, 0);
            break;

        case KVM_EXIT_DEBUG:
            result = VM_RESULT_SUCCESS;
            pthread_mutex_lock(&instance->thread_lock);
            if (0 != instance->debug && instance->debug->is_debugged)
            {
                for (unsigned index = 0; instance->config.vcpu_count > index; index++)
                    if (index != vcpu_index && instance->debug->thread_data[index].has_thread)
                        pthread_kill(instance->debug->thread_data[index].thread, SIG_VCPU_CANCEL);
                has_debug_event = 1;
            }
            pthread_mutex_unlock(&instance->thread_lock);
            break;

        case KVM_EXIT_HLT:
            result = vm_result(VM_ERROR_TERMINATED, 0);
            break;

        default:
            result = vm_result(VM_ERROR_VCPU, 0);
            break;
        }

        if (has_debug_log)
            vm_debug_log_exit(instance, vcpu_index, vcpu_run, result);
        if (!vm_result_check(result))
            goto exit;
    }

exit:
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
        instance->debug->thread_data[vcpu_index].thread = 0;
        instance->debug->thread_data[vcpu_index].has_thread = 0;
        instance->debug->thread_data[vcpu_index].vcpu_fd = -1;

        pthread_cond_broadcast(&instance->debug->stop_cvar);
        pthread_cond_broadcast(&instance->debug->cont_cvar);
        pthread_cond_broadcast(&instance->debug->wait_cvar);
    }
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

    struct vm_debug *debug;
    int is_terminated = 0, is_debugged = 0, single_step = 0;

    pthread_mutex_lock(&instance->thread_lock);

    if (instance->is_terminated || 0 == (debug = instance->debug) || !debug->is_debugged)
        goto skip_debug_event;

    debug->thread_data[vcpu_index].thread = pthread_self();
    debug->thread_data[vcpu_index].has_thread = 1;
    debug->thread_data[vcpu_index].vcpu_fd = vcpu_fd;

    debug->cont_count--;
    debug->stop_count++;
    if (instance->config.vcpu_count == debug->stop_count)
    {
        debug->is_stopped = 1;
        pthread_cond_broadcast(&debug->stop_cvar);

        if (0 != debug->events.stop)
            debug->events.stop(debug->events.self, instance, ~0ULL/*vcpu_index*/);
    }

    WAITCOND(
        debug->is_continued,
        &debug->wait_cvar);

    debug->stop_count--;
    debug->cont_count++;
    if (instance->config.vcpu_count == debug->cont_count)
    {
        debug->is_continued = 0;
        pthread_cond_broadcast(&debug->cont_cvar);
    }
    else
        WAITCOND(
            instance->config.vcpu_count == debug->cont_count,
            &debug->cont_cvar);

    is_debugged = debug->is_debugged;
    single_step = debug->single_step && vcpu_index == debug->vcpu_index;

skip_debug_event:
    is_terminated = instance->is_terminated;
    pthread_mutex_unlock(&instance->thread_lock);

    if (is_terminated)
        return vm_result(VM_ERROR_TERMINATED, 0);

    return vm_vcpu_debug(instance, vcpu_fd, is_debugged, single_step);

#undef WAITCOND
}

static vm_result_t vm_vcpu_init(vm_t *instance, unsigned vcpu_index, int vcpu_fd)
{
#if defined(__x86_64__)
    vm_result_t result;
    void *page = 0;
    vm_count_t length;
    vm_count_t cpu_data_address;
    struct arch_x64_seg_desc seg_desc;
    struct arch_x64_sseg_desc sseg_desc;
    struct kvm_regs regs;
    struct kvm_sregs sregs;

    page = malloc(sizeof(struct arch_x64_cpu_data));
    if (0 == page)
    {
        result = vm_result(VM_ERROR_RESOURCES, 0);
        goto exit;
    }

    cpu_data_address = instance->config.vcpu_table + vcpu_index * sizeof(struct arch_x64_cpu_data);
    arch_x64_cpu_data_init(page, cpu_data_address);
    length = sizeof(struct arch_x64_cpu_data);
    vm_mwrite(instance, page, cpu_data_address, &length);
    if (sizeof(struct arch_x64_cpu_data) != length)
    {
        result = vm_result(VM_ERROR_MEMORY, 0);
        goto exit;
    }

    memset(&regs, 0, sizeof regs);
    regs.rip = instance->config.vcpu_entry;
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

    result = VM_RESULT_SUCCESS;

exit:
    free(page);

    return result;
#endif
}

static vm_result_t vm_vcpu_debug(vm_t *instance, int vcpu_fd, int enable, int step)
{
    vm_result_t result;
    struct kvm_guest_debug debug;

    memset(&debug, 0, sizeof debug);
    if (enable)
        debug.control =
            KVM_GUESTDBG_ENABLE |
            KVM_GUESTDBG_USE_SW_BP |
            (step ? KVM_GUESTDBG_SINGLESTEP : 0);

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
        bufp += regb[regi];
    }
    for (; regc > regi; regi++)
    {
        regv = *(uint16_t *)((uint8_t *)&regs + regn[regi] + offsetof(struct kvm_segment, selector));
        bufp[3] = 0;
        bufp[2] = 0;
        bufp[1] = (uint8_t)(regv >> 8);
        bufp[0] = (uint8_t)(regv >> 0);
        bufp += regb[regi];
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
        bufp += regb[regi];
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

static void vm_debug_log_mmap(vm_t *instance)
{
    pthread_mutex_lock(&instance->mmap_lock);

    list_traverse(link, next, &instance->mmap_list)
    {
        vm_mmap_t *map = (vm_mmap_t *)link;
        instance->config.debug_log("mmap=%p,%p",
            map->guest_address,
            map->region_length);
    }

    pthread_mutex_unlock(&instance->mmap_lock);
}

static void vm_debug_log_cancel(vm_t *instance,
    unsigned vcpu_index, vm_result_t result)
{
    instance->config.debug_log("[%u] SIG_VCPU_CANCEL() = %s",
        vcpu_index,
        vm_result_error_string(result));
}

static void vm_debug_log_exit(vm_t *instance,
    unsigned vcpu_index, struct kvm_run *vcpu_run, vm_result_t result)
{
    switch (vcpu_run->exit_reason)
    {
    case KVM_EXIT_UNKNOWN:
        instance->config.debug_log("[%u] UNKNOWN(hardware_exit_reason=%llu) = %s",
            vcpu_index,
            (unsigned long long)vcpu_run->hw.hardware_exit_reason,
            vm_result_error_string(result));
        break;
    case KVM_EXIT_HLT:
        instance->config.debug_log("[%u] HLT() = %s",
            vcpu_index,
            vm_result_error_string(result));
        break;
    case KVM_EXIT_SHUTDOWN:
        instance->config.debug_log("[%u] SHUTDOWN() = %s",
            vcpu_index,
            vm_result_error_string(result));
        break;
    case KVM_EXIT_FAIL_ENTRY:
        instance->config.debug_log("[%u] FAIL_ENTRY(hardware_entry_failure_reason=0x%lx) = %s",
            vcpu_index,
            (unsigned long long)vcpu_run->fail_entry.hardware_entry_failure_reason,
            vm_result_error_string(result));
        break;
    case KVM_EXIT_INTERNAL_ERROR:
        instance->config.debug_log("[%u] INTERNAL_ERROR(suberror=%u) = %s",
            vcpu_index,
            (unsigned)vcpu_run->internal.suberror,
            vm_result_error_string(result));
        break;
    default:
        instance->config.debug_log("[%u] EXIT=%x() = %s",
            vcpu_index,
            vcpu_run->exit_reason,
            vm_result_error_string(result));
        break;
    }
}
