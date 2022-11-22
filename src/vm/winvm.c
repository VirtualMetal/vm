/**
 * @file vm/winvm.c
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
#include <winhvplatform.h>

struct vm
{
    vm_config_t config;
    WHV_PARTITION_HANDLE partition;
    SRWLOCK mmap_lock;
    list_link_t mmap_list;              /* protected by mmap_lock */
    SRWLOCK thread_lock;
    HANDLE thread;                      /* protected by thread_lock */
    vm_count_t thread_count;
    vm_result_t thread_result;
    unsigned
        is_terminated:1,                /* protected by thread_lock */
        is_debuggable:1;                /* immutable */
    vm_count_t debug_enable_count;      /* protected by thread_lock */
    struct vm_debug *debug;             /* protected by thread_lock */
    SRWLOCK vm_debug_lock;              /* vm_debug serialization lock */
};

struct vm_mmap
{
    list_link_t mmap_link;              /* protected by mmap_lock */
    PUINT8 head, tail;
    UINT64 head_length, tail_length;
    UINT64 guest_address;
    unsigned
        has_head:1,
        has_mapped_head:1,
        has_tail:1,
        has_mapped_tail:1;
};

struct vm_debug
{
    vm_debug_events_t events;
    CONDITION_VARIABLE stop_cvar, cont_cvar, wait_cvar;
        /* use condition variables for synchronization to streamline implementation across platforms */
    vm_count_t stop_count, cont_count;
    vm_count_t vcpu_index;
    vm_count_t bp_count;
    vm_count_t bp_address[64];
    UINT32 bp_value[64];
    unsigned
        is_debugged:1,
        is_stopped:1,
        is_continued:1,
        single_step:1,
        stop_on_start:1;
};

static vm_result_t vm_debug_internal(vm_t *instance, vm_count_t control, vm_count_t vcpu_index,
    void *buffer, vm_count_t *plength);
static DWORD WINAPI vm_thread(PVOID instance0);
static vm_result_t vm_thread_debug_event(vm_t *instance, UINT32 vcpu_index);
static vm_result_t vm_vcpu_init(vm_t *instance, UINT32 vcpu_index);
static vm_result_t vm_vcpu_debug(vm_t *instance, UINT32 vcpu_index, BOOL enable, BOOL step);
static vm_result_t vm_vcpu_getregs(vm_t *instance, UINT32 vcpu_index, void *buffer, vm_count_t *plength);
static vm_result_t vm_vcpu_setregs(vm_t *instance, UINT32 vcpu_index, void *buffer, vm_count_t *plength);
static void vm_debug_log_mmap(vm_t *instance);
static void vm_debug_log_exit(vm_t *instance,
    UINT32 vcpu_index, WHV_RUN_VP_EXIT_CONTEXT *exit_context, vm_result_t result);

#if defined(_M_X64)
/*
 * Register convenience macros
 *
 * Expected variables:
 *
 * - regn: register names
 * - regv: register values
 * - regc: register count
 * - regb: register bit length (REGBIT only)
 * - regl: register total byte length (REGBIT only)
 */
#define REGNAM(r)                       regn[regc] = WHvX64Register ## r, regc++
#define REGSET(r)                       regn[regc] = WHvX64Register ## r, regv[regc++]
#define REGVAL(...)                     (WHV_REGISTER_VALUE){ __VA_ARGS__ }
#define REGBIT(b)                       regb[regc - 1] = (b), regl += regb[regc - 1] >> 3
#endif

vm_result_t vm_create(const vm_config_t *config, vm_t **pinstance)
{
    vm_result_t result;
    vm_t *instance = 0;
    WHV_PARTITION_PROPERTY property;
    WHV_CAPABILITY capability;
    HRESULT hresult;

    *pinstance = 0;

    hresult = WHvGetCapability(
        WHvCapabilityCodeHypervisorPresent, &capability, sizeof capability, 0);
    if (FAILED(hresult) || !capability.HypervisorPresent)
    {
        result = vm_result(VM_ERROR_HYPERVISOR, hresult);
        goto exit;
    }

    instance = malloc(sizeof *instance);
    if (0 == instance)
    {
        result = vm_result(VM_ERROR_RESOURCES, 0);
        goto exit;
    }

    memset(instance, 0, sizeof *instance);
    instance->config = *config;
    InitializeSRWLock(&instance->mmap_lock);
    list_init(&instance->mmap_list);
    InitializeSRWLock(&instance->thread_lock);
    InitializeSRWLock(&instance->vm_debug_lock);

    hresult = WHvGetCapability(
        WHvCapabilityCodeExtendedVmExits, &capability, sizeof capability, 0);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_HYPERVISOR, hresult);
        goto exit;
    }
    instance->is_debuggable = !!capability.ExtendedVmExits.ExceptionExit;

    if (0 == instance->config.vcpu_count)
    {
        DWORD_PTR process_mask, system_mask;
        if (!GetProcessAffinityMask(GetCurrentProcess(), &process_mask, &system_mask))
        {
            result = vm_result(VM_ERROR_HYPERVISOR, GetLastError());
            goto exit;
        }
        for (instance->config.vcpu_count = 0; 0 != process_mask; process_mask >>= 1)
            instance->config.vcpu_count += process_mask & 1;
    }
    if (0 == instance->config.vcpu_count)
        instance->config.vcpu_count = 1;

    hresult = WHvCreatePartition(&instance->partition);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_HYPERVISOR, hresult);
        goto exit;
    }

    memset(&property, 0, sizeof property);
    property.ProcessorCount = (UINT32)instance->config.vcpu_count;
    hresult = WHvSetPartitionProperty(instance->partition,
        WHvPartitionPropertyCodeProcessorCount, &property, sizeof property);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_HYPERVISOR, hresult);
        goto exit;
    }

    hresult = WHvSetupPartition(instance->partition);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_HYPERVISOR, hresult);
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
    while (!list_is_empty(&instance->mmap_list))
        vm_munmap(instance, (vm_mmap_t *)instance->mmap_list.next);

    if (0 != instance->partition)
        WHvDeletePartition(instance->partition);

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
    SYSTEM_INFO sys_info;
    HANDLE mapping = 0;
    MEMORY_BASIC_INFORMATION mem_info;
    HRESULT hresult;

    *pmap = 0;

    GetSystemInfo(&sys_info);
    length = (length + sys_info.dwPageSize - 1) & ~(sys_info.dwPageSize - 1);

    if (0 != ((UINT_PTR)host_address & (sys_info.dwPageSize - 1)) ||
        0 != (guest_address & (sys_info.dwPageSize - 1)) ||
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

    if (0 == host_address && -1 == file)
    {
        map->head_length = length;
        map->head = VirtualAlloc(0, length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (0 == map->head)
        {
            result = vm_result(VM_ERROR_MEMORY, GetLastError());
            goto exit;
        }
        map->has_head = 1;
    }
    else if (0 == host_address && -1 != file)
    {
        mapping = CreateFileMappingW((HANDLE)(UINT_PTR)file,
            0, PAGE_WRITECOPY, 0, 0, 0);
        if (0 == mapping)
        {
            result = vm_result(VM_ERROR_MEMORY, GetLastError());
            goto exit;
        }

        map->head = MapViewOfFile(mapping, FILE_MAP_COPY, 0, 0, 0);
        if (0 == map->head)
        {
            result = vm_result(VM_ERROR_MEMORY, GetLastError());
            goto exit;
        }
        map->has_head = 1;

        if (0 == VirtualQuery(map->head, &mem_info, sizeof mem_info))
        {
            result = vm_result(VM_ERROR_MEMORY, GetLastError());
            goto exit;
        }

        map->head_length = mem_info.RegionSize;
        if (length > map->head_length)
        {
            map->tail_length = length - map->head_length;
            map->tail = VirtualAlloc(0, map->tail_length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (0 == map->tail)
            {
                result = vm_result(VM_ERROR_MEMORY, GetLastError());
                goto exit;
            }
            map->has_tail = 1;
        }
    }
    else if (0 != host_address && -1 == file)
    {
        map->head_length = length;
        map->head = host_address;
    }
    else if (0 != host_address && -1 != file)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    hresult = WHvMapGpaRange(instance->partition,
        map->head, map->guest_address, map->head_length,
        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_HYPERVISOR, hresult);
        goto exit;
    }
    map->has_mapped_head = 1;

    if (map->has_tail)
    {
        hresult = WHvMapGpaRange(instance->partition,
            map->tail, map->guest_address + map->head_length, map->tail_length,
            WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute);
        if (FAILED(hresult))
        {
            result = vm_result(VM_ERROR_HYPERVISOR, hresult);
            goto exit;
        }
        map->has_mapped_tail = 1;
    }

    AcquireSRWLockExclusive(&instance->mmap_lock);
    list_insert_after(&instance->mmap_list, &map->mmap_link);
    ReleaseSRWLockExclusive(&instance->mmap_lock);

    *pmap = map;
    result = VM_RESULT_SUCCESS;

exit:
    if (0 != mapping)
        CloseHandle(mapping);

    if (!vm_result_check(result) && 0 != map)
        vm_munmap(instance, map);

    return result;
}

vm_result_t vm_munmap(vm_t *instance, vm_mmap_t *map)
{
    AcquireSRWLockExclusive(&instance->mmap_lock);
    list_remove(&map->mmap_link);
    ReleaseSRWLockExclusive(&instance->mmap_lock);

    if (map->has_mapped_tail)
    {
        WHvUnmapGpaRange(instance->partition,
            map->guest_address + map->head_length, map->tail_length);
        WHvUnmapGpaRange(instance->partition,
            map->guest_address, map->head_length);
    }
    else if (map->has_mapped_head)
        WHvUnmapGpaRange(instance->partition,
            map->guest_address, map->head_length);

    if (map->has_tail)
    {
        VirtualFree(map->tail, 0, MEM_RELEASE);
        UnmapViewOfFile(map->head);
    }
    else if (map->has_head)
        VirtualFree(map->head, 0, MEM_RELEASE);

    free(map);

    return VM_RESULT_SUCCESS;
}

vm_result_t vm_mmap_read(vm_mmap_t *map,
    vm_count_t offset, void *buffer, vm_count_t *plength)
{
    vm_count_t remain = *plength;
    vm_count_t head_length = 0, tail_length = 0;
    vm_count_t end_offset;

    if (offset >= map->head_length)
    {
        offset -= map->head_length;
        goto tail;
    }

    end_offset = offset + remain;
    if (end_offset > map->head_length)
        end_offset = map->head_length;

    head_length = end_offset - offset;
    memcpy(buffer, map->head + offset, head_length);

    offset = 0;
    remain -= head_length;

tail:
    if (offset >= map->tail_length)
        goto exit;

    end_offset = offset + remain;
    if (end_offset > map->tail_length)
        end_offset = map->tail_length;

    tail_length = end_offset - offset;
    memcpy((PUINT8)buffer + head_length, map->tail + offset, tail_length);

exit:
    *plength = head_length + tail_length;
    return VM_RESULT_SUCCESS;
}

vm_result_t vm_mmap_write(vm_mmap_t *map,
    void *buffer, vm_count_t offset, vm_count_t *plength)
{
    vm_count_t remain = *plength;
    vm_count_t head_length = 0, tail_length = 0;
    vm_count_t end_offset;

    if (offset >= map->head_length)
    {
        offset -= map->head_length;
        goto tail;
    }

    end_offset = offset + remain;
    if (end_offset > map->head_length)
        end_offset = map->head_length;

    head_length = end_offset - offset;
    memcpy(map->head + offset, buffer, head_length);

    offset = 0;
    remain -= head_length;

tail:
    if (offset >= map->tail_length)
        goto exit;

    end_offset = offset + remain;
    if (end_offset > map->tail_length)
        end_offset = map->tail_length;

    tail_length = end_offset - offset;
    memcpy(map->tail + offset, (PUINT8)buffer + head_length, tail_length);

exit:
    *plength = head_length + tail_length;
    return VM_RESULT_SUCCESS;
}

vm_result_t vm_mread(vm_t *instance,
    vm_count_t guest_address, void *buffer, vm_count_t *plength)
{
    vm_count_t length = 0;

    AcquireSRWLockExclusive(&instance->mmap_lock);

    list_traverse(link, next, &instance->mmap_list)
    {
        vm_mmap_t *map = (vm_mmap_t *)link;
        if (map->guest_address <= guest_address &&
            guest_address < map->guest_address + map->head_length + map->tail_length)
        {
            length = *plength;
            vm_mmap_read(map, guest_address - map->guest_address, buffer, &length);
            break;
        }
    }

    ReleaseSRWLockExclusive(&instance->mmap_lock);

    *plength = length;
    return VM_RESULT_SUCCESS;
}

vm_result_t vm_mwrite(vm_t *instance,
    void *buffer, vm_count_t guest_address, vm_count_t *plength)
{
    vm_count_t length = 0;

    AcquireSRWLockExclusive(&instance->mmap_lock);

    list_traverse(link, next, &instance->mmap_list)
    {
        vm_mmap_t *map = (vm_mmap_t *)link;
        if (map->guest_address <= guest_address &&
            guest_address < map->guest_address + map->head_length + map->tail_length)
        {
            length = *plength;
            vm_mmap_write(map, buffer, guest_address - map->guest_address, &length);
            break;
        }
    }

    ReleaseSRWLockExclusive(&instance->mmap_lock);

    *plength = length;
    return VM_RESULT_SUCCESS;
}

vm_result_t vm_start(vm_t *instance)
{
    vm_result_t result;

    if (0 != instance->thread)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    if (instance->config.debug_log)
        vm_debug_log_mmap(instance);

    InterlockedExchange64(&instance->thread_result, VM_RESULT_SUCCESS);

    AcquireSRWLockExclusive(&instance->thread_lock);

    if (!instance->is_terminated)
    {
        instance->thread_count = instance->config.vcpu_count;
        instance->thread = CreateThread(0, 0, vm_thread, instance, 0, 0);
        if (0 == instance->thread)
            result = vm_result(VM_ERROR_VCPU, GetLastError());
    }
    else
        result = vm_result(VM_ERROR_TERMINATED, 0);

    ReleaseSRWLockExclusive(&instance->thread_lock);

    if (0 == instance->thread)
        goto exit;

    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

vm_result_t vm_wait(vm_t *instance)
{
    vm_result_t result;

    if (0 == instance->thread)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    WaitForSingleObject(instance->thread, INFINITE);

    AcquireSRWLockExclusive(&instance->thread_lock);

    CloseHandle(instance->thread);
    instance->thread = 0;

    ReleaseSRWLockExclusive(&instance->thread_lock);

    result = InterlockedCompareExchange64(&instance->thread_result, 0, 0);
    if (VM_ERROR_TERMINATED == vm_result_error(result))
        result = VM_RESULT_SUCCESS;

exit:
    return result;
}

vm_result_t vm_terminate(vm_t *instance)
{
    /*
     * We first set is_terminated and then cancel the virtual CPU. In vm_thread
     * we first create the virtual CPU and then check is_terminated. This
     * interleaving ensures that termination will work even if it happens while
     * the instance is being started.
     */

    AcquireSRWLockExclusive(&instance->thread_lock);

    instance->is_terminated = 1;
    if (0 != instance->thread)
        WHvCancelRunVirtualProcessor(instance->partition, 0, 0);
    if (0 != instance->debug)
    {
        WakeAllConditionVariable(&instance->debug->stop_cvar);
        WakeAllConditionVariable(&instance->debug->cont_cvar);
        WakeAllConditionVariable(&instance->debug->wait_cvar);
    }

    ReleaseSRWLockExclusive(&instance->thread_lock);

    return VM_RESULT_SUCCESS;
}

vm_result_t vm_debug(vm_t *instance, vm_count_t control, vm_count_t vcpu_index,
    void *buffer, vm_count_t *plength)
{
    vm_result_t result;

    AcquireSRWLockExclusive(&instance->vm_debug_lock);
    AcquireSRWLockExclusive(&instance->thread_lock);

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
    ReleaseSRWLockExclusive(&instance->thread_lock);
    ReleaseSRWLockExclusive(&instance->vm_debug_lock);

    if (!vm_result_check(result) && 0 != plength)
        *plength = 0;

    return result;
}

static vm_result_t vm_debug_internal(vm_t *instance, vm_count_t control, vm_count_t vcpu_index,
    void *buffer, vm_count_t *plength)
{
    vm_result_t result;
    struct vm_debug *debug;

    debug = instance->debug;

    switch (control)
    {
    case VM_DEBUG_ATTACH:
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

        debug = malloc(sizeof *debug);
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
        InitializeConditionVariable(&debug->stop_cvar);
        InitializeConditionVariable(&debug->cont_cvar);
        InitializeConditionVariable(&debug->wait_cvar);
        debug->cont_count = instance->config.vcpu_count;
        debug->is_debugged = 1;

        instance->debug = debug;
        break;

    case VM_DEBUG_DETACH:
        if (instance->is_terminated)
        {
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

        for (vm_count_t index = debug->bp_count - 1; debug->bp_count > index; index--)
        {
            vm_count_t length = sizeof debug->bp_address[index];
            vm_debug_internal(instance, VM_DEBUG_DELBP, 0, &debug->bp_address[index], &length);
        }

        debug->is_debugged = 0;
        vm_debug_internal(instance, VM_DEBUG_CONT, 0, 0, 0);

        free(debug);
        instance->debug = 0;
        break;

    case VM_DEBUG_BREAK:
        if (instance->is_terminated)
        {
            result = vm_result(VM_ERROR_TERMINATED, 0);
            goto exit;
        }
        if (debug->is_stopped)
            break;

        debug->stop_on_start = 1;
        if (0 != instance->thread)
        {
            for (UINT32 index = 0; instance->config.vcpu_count > index; index++)
                WHvCancelRunVirtualProcessor(instance->partition, index, 0);
            while (!instance->is_terminated &&
                !debug->is_stopped)
                SleepConditionVariableSRW(&debug->stop_cvar, &instance->thread_lock, INFINITE, 0);
            if (instance->is_terminated)
            {
                result = vm_result(VM_ERROR_TERMINATED, 0);
                goto exit;
            }
        }
        break;

    case VM_DEBUG_CONT:
    case VM_DEBUG_STEP:
        if (instance->is_terminated)
        {
            result = vm_result(VM_ERROR_TERMINATED, 0);
            goto exit;
        }
        if (!debug->is_stopped)
            break;

        debug->stop_on_start = 0;
        debug->is_stopped = 0;
        if (0 != instance->thread)
        {
            debug->is_continued = 1;
            debug->vcpu_index = vcpu_index;
            debug->single_step = VM_DEBUG_STEP == control;
            WakeAllConditionVariable(&debug->wait_cvar);
            while (!instance->is_terminated &&
                debug->is_continued)
                SleepConditionVariableSRW(&debug->cont_cvar, &instance->thread_lock, INFINITE, 0);
            if (instance->is_terminated)
            {
                result = vm_result(VM_ERROR_TERMINATED, 0);
                goto exit;
            }
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
            result = vm_vcpu_getregs(instance, (UINT32)vcpu_index, buffer, plength);
        else
            result = vm_vcpu_setregs(instance, (UINT32)vcpu_index, buffer, plength);
        if (!vm_result_check(result))
            goto exit;
        break;

    case VM_DEBUG_SETBP:
    case VM_DEBUG_DELBP:
        if (instance->is_terminated)
        {
            result = vm_result(VM_ERROR_TERMINATED, 0);
            goto exit;
        }
        if (!debug->is_stopped || sizeof(vm_count_t) > *plength)
        {
            result = vm_result(VM_ERROR_MISUSE, 0);
            goto exit;
        }

        {
            vm_count_t bp_address = *(vm_count_t *)buffer;
            vm_count_t index;
#if defined(_M_X64)
            UINT32 bp_value, bp_instr = 0xcc/* INT3 instruction */;
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

static DWORD WINAPI vm_thread(PVOID instance0)
{
    vm_result_t result;
    vm_t *instance = instance0;
    UINT32 vcpu_index;
    BOOL has_vcpu = FALSE;
    BOOL is_terminated, has_debug_event, has_debug_log;
    HANDLE next_thread = 0;
    WHV_RUN_VP_EXIT_CONTEXT exit_context;
    HRESULT hresult;

    vcpu_index = (UINT32)(instance->config.vcpu_count - instance->thread_count);

    hresult = WHvCreateVirtualProcessor(instance->partition, vcpu_index, 0);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_VCPU, hresult);
        goto exit;
    }
    has_vcpu = TRUE;

    AcquireSRWLockExclusive(&instance->thread_lock);
    is_terminated = instance->is_terminated;
    has_debug_event = 0 != instance->debug && instance->debug->is_debugged &&
        instance->debug->stop_on_start;
    ReleaseSRWLockExclusive(&instance->thread_lock);
    if (is_terminated)
    {
        result = vm_result(VM_ERROR_TERMINATED, 0);
        goto exit;
    }

    /*
     * The following code block is thread-safe because the CreateThread call
     * ensures that we run in a lockstep fashion. This is because the call
     * must act as a barrier: by the time the new thread is created it must
     * observe the world as if all previous code has run.
     */
    if (1 < instance->thread_count)
    {
        instance->thread_count--;
        next_thread = CreateThread(0, 0, vm_thread, instance, 0, 0);
        if (0 == next_thread)
        {
            result = vm_result(VM_ERROR_VCPU, GetLastError());
            goto exit;
        }
    }

    result = vm_vcpu_init(instance, vcpu_index);
    if (!vm_result_check(result))
        goto exit;

    has_debug_log = !!instance->config.debug_log;

    for (;;)
    {
        if (has_debug_event)
        {
            has_debug_event = FALSE;
            result = vm_thread_debug_event(instance, vcpu_index);
            if (!vm_result_check(result))
                goto exit;
        }

        hresult = WHvRunVirtualProcessor(instance->partition,
            vcpu_index, &exit_context, sizeof exit_context);
        if (FAILED(hresult))
        {
            result = vm_result(VM_ERROR_VCPU, hresult);
            goto exit;
        }

        switch (exit_context.ExitReason)
        {
        case WHvRunVpExitReasonX64IoPortAccess:
            result = vm_result(VM_ERROR_VCPU, 0);
            break;

        case WHvRunVpExitReasonMemoryAccess:
            result = vm_result(VM_ERROR_VCPU, 0);
            break;

        case WHvRunVpExitReasonException:
            result = VM_RESULT_SUCCESS;
            AcquireSRWLockExclusive(&instance->thread_lock);
            if (0 != instance->debug && instance->debug->is_debugged)
            {
                instance->debug->stop_on_start = 1;
                for (UINT32 index = 0; instance->config.vcpu_count > index; index++)
                    if (index != vcpu_index)
                        WHvCancelRunVirtualProcessor(instance->partition, index, 0);
                has_debug_event = TRUE;
            }
            ReleaseSRWLockExclusive(&instance->thread_lock);
            break;

        case WHvRunVpExitReasonX64Halt:
            result = vm_result(VM_ERROR_TERMINATED, 0);
            break;

        case WHvRunVpExitReasonCanceled:
            result = VM_RESULT_SUCCESS;
            has_debug_event = FALSE;
            AcquireSRWLockExclusive(&instance->thread_lock);
            if (instance->is_terminated)
                result = vm_result(VM_ERROR_TERMINATED, 0);
            else if (0 != instance->debug && instance->debug->is_debugged)
                has_debug_event = TRUE;
            ReleaseSRWLockExclusive(&instance->thread_lock);
            break;

        default:
            result = vm_result(VM_ERROR_VCPU, 0);
            break;
        }

        if (has_debug_log)
            vm_debug_log_exit(instance, vcpu_index, &exit_context, result);
        if (!vm_result_check(result))
            goto exit;
    }

exit:
    if (!vm_result_check(result))
        InterlockedCompareExchange64(&instance->thread_result, result, VM_RESULT_SUCCESS);

    AcquireSRWLockExclusive(&instance->thread_lock);
    instance->is_terminated = 1;
    WHvCancelRunVirtualProcessor(instance->partition, (vcpu_index + 1) % instance->config.vcpu_count, 0);
    if (0 != instance->debug)
    {
        WakeAllConditionVariable(&instance->debug->stop_cvar);
        WakeAllConditionVariable(&instance->debug->cont_cvar);
        WakeAllConditionVariable(&instance->debug->wait_cvar);
    }
    ReleaseSRWLockExclusive(&instance->thread_lock);

    if (0 != next_thread)
    {
        WaitForSingleObject(next_thread, INFINITE);
        CloseHandle(next_thread);
    }

    if (has_vcpu)
        WHvDeleteVirtualProcessor(instance->partition, vcpu_index);

    return 0;
}

static vm_result_t vm_thread_debug_event(vm_t *instance, UINT32 vcpu_index)
{
#define WAITCOND(cond, cvar)            \
    do                                  \
    {                                   \
        if (instance->is_terminated || 0 == (debug = instance->debug) || !debug->is_debugged)\
            goto skip_debug_event;      \
        if (cond)                       \
            break;                      \
        SleepConditionVariableSRW(cvar, &instance->thread_lock, INFINITE, 0);\
    } while (1)

    struct vm_debug *debug;
    BOOL is_terminated = FALSE, is_debugged = FALSE, single_step = FALSE;

    AcquireSRWLockExclusive(&instance->thread_lock);

    if (instance->is_terminated || 0 == (debug = instance->debug) || !debug->is_debugged)
        goto skip_debug_event;

    debug->cont_count--;
    debug->stop_count++;
    if (instance->config.vcpu_count == debug->stop_count)
    {
        debug->is_stopped = 1;
        WakeAllConditionVariable(&debug->stop_cvar);

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
        WakeAllConditionVariable(&debug->cont_cvar);
    }
    else
        WAITCOND(
            instance->config.vcpu_count == debug->cont_count,
            &debug->cont_cvar);

    is_debugged = debug->is_debugged;
    single_step = debug->single_step && vcpu_index == debug->vcpu_index;

skip_debug_event:
    is_terminated = instance->is_terminated;
    ReleaseSRWLockExclusive(&instance->thread_lock);

    if (is_terminated)
        return vm_result(VM_ERROR_TERMINATED, 0);

    return vm_vcpu_debug(instance, vcpu_index, is_debugged, single_step);

#undef WAITCOND
}

static vm_result_t vm_vcpu_init(vm_t *instance, UINT32 vcpu_index)
{
#if defined(_M_X64)
    vm_result_t result;
    void *page = 0;
    vm_count_t length;
    vm_count_t cpu_data_address;
    struct arch_x64_seg_desc seg_desc;
    struct arch_x64_sseg_desc sseg_desc;
    WHV_REGISTER_NAME regn[128];
    WHV_REGISTER_VALUE regv[128];
    UINT32 regc;
    HRESULT hresult;

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

    regc = 0;
    REGSET(Rax) = REGVAL(0);
    REGSET(Rcx) = REGVAL(0);
    REGSET(Rdx) = REGVAL(0);
    REGSET(Rbx) = REGVAL(0);
    REGSET(Rsp) = REGVAL(0);
    REGSET(Rbp) = REGVAL(0);
    REGSET(Rsi) = REGVAL(0);
    REGSET(Rdi) = REGVAL(0);
    REGSET(R8) = REGVAL(0);
    REGSET(R9) = REGVAL(0);
    REGSET(R10) = REGVAL(0);
    REGSET(R11) = REGVAL(0);
    REGSET(R12) = REGVAL(0);
    REGSET(R13) = REGVAL(0);
    REGSET(R14) = REGVAL(0);
    REGSET(R15) = REGVAL(0);
    REGSET(Rip) = REGVAL(.Reg64 = instance->config.vcpu_entry);
    REGSET(Rflags) = REGVAL(.Reg64 = 2);

    seg_desc = ((struct arch_x64_cpu_data *)page)->gdt.km_cs;
    REGSET(Cs) = REGVAL(
        .Segment.Selector = (UINT16)&((struct arch_x64_gdt *)0)->km_cs,
        .Segment.Base = (UINT64)(seg_desc.address0 | (seg_desc.address1 << 24)),
        .Segment.Limit = (UINT32)(seg_desc.limit0 | (seg_desc.limit1 << 16)),
        .Segment.SegmentType = seg_desc.type,
        .Segment.NonSystemSegment = seg_desc.s,
        .Segment.DescriptorPrivilegeLevel = seg_desc.dpl,
        .Segment.Present = seg_desc.p,
        .Segment.Available = seg_desc.avl,
        .Segment.Long = seg_desc.l,
        .Segment.Default = seg_desc.db,
        .Segment.Granularity = seg_desc.g);
    seg_desc = ((struct arch_x64_cpu_data *)page)->gdt.km_ds;
    REGSET(Ds) = REGVAL(
        .Segment.Selector = (UINT16)&((struct arch_x64_gdt *)0)->km_ds,
        .Segment.Base = (UINT64)(seg_desc.address0 | (seg_desc.address1 << 24)),
        .Segment.Limit = (UINT32)(seg_desc.limit0 | (seg_desc.limit1 << 16)),
        .Segment.SegmentType = seg_desc.type,
        .Segment.NonSystemSegment = seg_desc.s,
        .Segment.DescriptorPrivilegeLevel = seg_desc.dpl,
        .Segment.Present = seg_desc.p,
        .Segment.Available = seg_desc.avl,
        .Segment.Long = seg_desc.l,
        .Segment.Default = seg_desc.db,
        .Segment.Granularity = seg_desc.g);
    REGSET(Es) = REGVAL(
        .Segment.Selector = (UINT16)&((struct arch_x64_gdt *)0)->km_ds,
        .Segment.Base = (UINT64)(seg_desc.address0 | (seg_desc.address1 << 24)),
        .Segment.Limit = (UINT32)(seg_desc.limit0 | (seg_desc.limit1 << 16)),
        .Segment.SegmentType = seg_desc.type,
        .Segment.NonSystemSegment = seg_desc.s,
        .Segment.DescriptorPrivilegeLevel = seg_desc.dpl,
        .Segment.Present = seg_desc.p,
        .Segment.Available = seg_desc.avl,
        .Segment.Long = seg_desc.l,
        .Segment.Default = seg_desc.db,
        .Segment.Granularity = seg_desc.g);
    REGSET(Ss) = REGVAL(
        .Segment.Selector = (UINT16)&((struct arch_x64_gdt *)0)->km_ds,
        .Segment.Base = (UINT64)(seg_desc.address0 | (seg_desc.address1 << 24)),
        .Segment.Limit = (UINT32)(seg_desc.limit0 | (seg_desc.limit1 << 16)),
        .Segment.SegmentType = seg_desc.type,
        .Segment.NonSystemSegment = seg_desc.s,
        .Segment.DescriptorPrivilegeLevel = seg_desc.dpl,
        .Segment.Present = seg_desc.p,
        .Segment.Available = seg_desc.avl,
        .Segment.Long = seg_desc.l,
        .Segment.Default = seg_desc.db,
        .Segment.Granularity = seg_desc.g);
    sseg_desc = ((struct arch_x64_cpu_data *)page)->gdt.tss;
    REGSET(Tr) = REGVAL(
        .Segment.Selector = (UINT16)&((struct arch_x64_gdt *)0)->tss,
        .Segment.Base = (UINT64)(sseg_desc.address0 | (sseg_desc.address1 << 24) | (sseg_desc.address2 << 32)),
        .Segment.Limit = (UINT32)(sseg_desc.limit0 | (sseg_desc.limit1 << 16)),
        .Segment.SegmentType = 11,      /* TYPE=11 (64-bit busy TSS) */
        .Segment.NonSystemSegment = sseg_desc.s,
        .Segment.DescriptorPrivilegeLevel = sseg_desc.dpl,
        .Segment.Present = sseg_desc.p,
        .Segment.Available = sseg_desc.avl,
        .Segment.Long = sseg_desc.l,
        .Segment.Default = sseg_desc.db,
        .Segment.Granularity = sseg_desc.g);
    REGSET(Gdtr) = REGVAL(
        .Table.Base = cpu_data_address + (vm_count_t)&((struct arch_x64_cpu_data *)0)->gdt,
        .Table.Limit = sizeof(struct arch_x64_gdt));
    REGSET(Cr0) = REGVAL(.Reg64 = 0x80000011);    /* PG=1,MP=1,PE=1 */
    REGSET(Cr3) = REGVAL(.Reg64 = instance->config.page_table);
    REGSET(Cr4) = REGVAL(.Reg64 = 0x00000020);    /* PAE=1 */
    REGSET(Efer) = REGVAL(.Reg64 = 0x00000500);   /* LMA=1,LME=1 */

    hresult = WHvSetVirtualProcessorRegisters(instance->partition,
        vcpu_index, regn, regc, regv);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_VCPU, hresult);
        goto exit;
    }

    result = VM_RESULT_SUCCESS;

exit:
    free(page);

    return result;
#endif
}

static vm_result_t vm_vcpu_debug(vm_t *instance, UINT32 vcpu_index, BOOL enable, BOOL step)
{
#if defined(_M_X64)
    vm_result_t result;
    WHV_PARTITION_PROPERTY property;
    WHV_REGISTER_NAME regn[1];
    WHV_REGISTER_VALUE regv[1];
    UINT32 regc;
    UINT64 rflags;
    HRESULT hresult;

    AcquireSRWLockExclusive(&instance->thread_lock);
    if (( enable && 0 == instance->debug_enable_count++) ||
        (!enable && 1 == instance->debug_enable_count--))
    {
        memset(&property, 0, sizeof property);
        property.ExtendedVmExits.ExceptionExit = !!enable;
        hresult = WHvSetPartitionProperty(instance->partition,
            WHvPartitionPropertyCodeExtendedVmExits, &property, sizeof property);
        if (FAILED(hresult))
        {
            result = vm_result(VM_ERROR_HYPERVISOR, hresult);
            goto exit;
        }

        memset(&property, 0, sizeof property);
        property.ExceptionExitBitmap = enable ?
            (1 << WHvX64ExceptionTypeDebugTrapOrFault) | (1 << WHvX64ExceptionTypeBreakpointTrap) :
            0;
        hresult = WHvSetPartitionProperty(instance->partition,
            WHvPartitionPropertyCodeExceptionExitBitmap, &property, sizeof property);
        if (FAILED(hresult))
        {
            result = vm_result(VM_ERROR_HYPERVISOR, hresult);
            goto exit;
        }
    }
    ReleaseSRWLockExclusive(&instance->thread_lock);

    regc = 0;
    REGNAM(Rflags);

    hresult = WHvGetVirtualProcessorRegisters(instance->partition,
        vcpu_index, regn, regc, regv);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_VCPU, hresult);
        goto exit;
    }

    rflags = regv[0].Reg64 & ~0x100;
    if (enable && step)
        rflags |= 0x100; /* TF bit */

    regc = 0;
    REGSET(Rflags) = REGVAL(.Reg64 = rflags);

    hresult = WHvSetVirtualProcessorRegisters(instance->partition,
        vcpu_index, regn, regc, regv);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_VCPU, hresult);
        goto exit;
    }

    result = VM_RESULT_SUCCESS;

exit:
    return result;
#endif
}

static vm_result_t vm_vcpu_getregs(vm_t *instance, UINT32 vcpu_index, void *buffer, vm_count_t *plength)
{
#if defined(_M_X64)
    vm_result_t result;
    WHV_REGISTER_NAME regn[128];
    WHV_REGISTER_VALUE regv[128];
    UINT8 regb[128];
    UINT32 regi, genc, regc, regl;
    PUINT8 bufp;
    vm_count_t length;
    HRESULT hresult;

    length = *plength;
    *plength = 0;

    /* see gdb/features/i386/64bit-core.xml; we omit the floating point registers */
    regc = 0; regl = 0;
    REGNAM(Rax); REGBIT(64);
    REGNAM(Rbx); REGBIT(64);
    REGNAM(Rcx); REGBIT(64);
    REGNAM(Rdx); REGBIT(64);
    REGNAM(Rsi); REGBIT(64);
    REGNAM(Rdi); REGBIT(64);
    REGNAM(Rbp); REGBIT(64);
    REGNAM(Rsp); REGBIT(64);
    REGNAM(R8); REGBIT(64);
    REGNAM(R9); REGBIT(64);
    REGNAM(R10); REGBIT(64);
    REGNAM(R11); REGBIT(64);
    REGNAM(R12); REGBIT(64);
    REGNAM(R13); REGBIT(64);
    REGNAM(R14); REGBIT(64);
    REGNAM(R15); REGBIT(64);
    REGNAM(Rip); REGBIT(64);
    REGNAM(Rflags); REGBIT(32);
    genc = regc; /* general register count */
    REGNAM(Cs); REGBIT(32);
    REGNAM(Ss); REGBIT(32);
    REGNAM(Ds); REGBIT(32);
    REGNAM(Es); REGBIT(32);
    REGNAM(Fs); REGBIT(32);
    REGNAM(Gs); REGBIT(32);

    if (regl > length)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    hresult = WHvGetVirtualProcessorRegisters(instance->partition,
        vcpu_index, regn, regc, regv);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_VCPU, hresult);
        goto exit;
    }

    bufp = buffer;
    for (regi = 0; genc > regi; regi++)
    {
        switch (regb[regi])
        {
        case 64:
            bufp[7] = (UINT8)(regv[regi].Reg64 >> 56);
            bufp[6] = (UINT8)(regv[regi].Reg64 >> 48);
            bufp[5] = (UINT8)(regv[regi].Reg64 >> 40);
            bufp[4] = (UINT8)(regv[regi].Reg64 >> 32);
            /* fallthrough */
        case 32:
            bufp[3] = (UINT8)(regv[regi].Reg64 >> 24);
            bufp[2] = (UINT8)(regv[regi].Reg64 >> 16);
            bufp[1] = (UINT8)(regv[regi].Reg64 >> 8);
            bufp[0] = (UINT8)(regv[regi].Reg64 >> 0);
            break;
        }
        bufp += regb[regi] >> 3;
    }
    for (; regc > regi; regi++)
    {
        bufp[3] = 0;
        bufp[2] = 0;
        bufp[1] = (UINT8)(regv[regi].Segment.Selector >> 8);
        bufp[0] = (UINT8)(regv[regi].Segment.Selector >> 0);
        bufp += regb[regi] >> 3;
    }

    *plength = regl;
    result = VM_RESULT_SUCCESS;

exit:
    return result;
#endif
}

static vm_result_t vm_vcpu_setregs(vm_t *instance, UINT32 vcpu_index, void *buffer, vm_count_t *plength)
{
#if defined(_M_X64)
    vm_result_t result;
    WHV_REGISTER_NAME regn[128];
    WHV_REGISTER_VALUE regv[128];
    UINT8 regb[128];
    UINT32 regi, regc, regl;
    PUINT8 bufp;
    vm_count_t length;
    HRESULT hresult;

    length = *plength;
    *plength = 0;

    /* see gdb/features/i386/64bit-core.xml; we omit the segment and floating point registers */
    regc = 0; regl = 0;
    REGNAM(Rax); REGBIT(64);
    REGNAM(Rbx); REGBIT(64);
    REGNAM(Rcx); REGBIT(64);
    REGNAM(Rdx); REGBIT(64);
    REGNAM(Rsi); REGBIT(64);
    REGNAM(Rdi); REGBIT(64);
    REGNAM(Rbp); REGBIT(64);
    REGNAM(Rsp); REGBIT(64);
    REGNAM(R8); REGBIT(64);
    REGNAM(R9); REGBIT(64);
    REGNAM(R10); REGBIT(64);
    REGNAM(R11); REGBIT(64);
    REGNAM(R12); REGBIT(64);
    REGNAM(R13); REGBIT(64);
    REGNAM(R14); REGBIT(64);
    REGNAM(R15); REGBIT(64);
    REGNAM(Rip); REGBIT(64);
    REGNAM(Rflags); REGBIT(32);

    if (regl > length)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    memset(regv, 0, sizeof regv);

    bufp = buffer;
    for (regi = 0; regc > regi; regi++)
    {
        regv[regi].Reg64 = 0;
        switch (regb[regi])
        {
        case 64:
            regv[regi].Reg64 |= (UINT64)bufp[7] << 56;
            regv[regi].Reg64 |= (UINT64)bufp[6] << 48;
            regv[regi].Reg64 |= (UINT64)bufp[5] << 40;
            regv[regi].Reg64 |= (UINT64)bufp[4] << 32;
            /* fallthrough */
        case 32:
            regv[regi].Reg64 |= (UINT64)bufp[3] << 24;
            regv[regi].Reg64 |= (UINT64)bufp[2] << 16;
            regv[regi].Reg64 |= (UINT64)bufp[1] << 8;
            regv[regi].Reg64 |= (UINT64)bufp[0] << 0;
            break;
        }
        bufp += regb[regi] >> 3;
    }

    hresult = WHvSetVirtualProcessorRegisters(instance->partition,
        vcpu_index, regn, regc, regv);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_VCPU, hresult);
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
    AcquireSRWLockExclusive(&instance->mmap_lock);

    list_traverse(link, next, &instance->mmap_list)
    {
        vm_mmap_t *map = (vm_mmap_t *)link;
        instance->config.debug_log("mmap=%p,%p",
            map->guest_address,
            map->head_length + map->tail_length);
    }

    ReleaseSRWLockExclusive(&instance->mmap_lock);
}

static void vm_debug_log_exit(vm_t *instance,
    UINT32 vcpu_index, WHV_RUN_VP_EXIT_CONTEXT *exit_context, vm_result_t result)
{
    char *exit_reason_str;

    switch (exit_context->ExitReason)
    {
    case WHvRunVpExitReasonNone:
        exit_reason_str = "None";
        break;
    case WHvRunVpExitReasonMemoryAccess:
        exit_reason_str = "MemoryAccess";
        break;
    case WHvRunVpExitReasonX64IoPortAccess:
        exit_reason_str = "X64IoPortAccess";
        break;
    case WHvRunVpExitReasonUnrecoverableException:
        exit_reason_str = "UnrecoverableException";
        break;
    case WHvRunVpExitReasonInvalidVpRegisterValue:
        exit_reason_str = "InvalidVpRegisterValue";
        break;
    case WHvRunVpExitReasonUnsupportedFeature:
        exit_reason_str = "UnsupportedFeature";
        break;
    case WHvRunVpExitReasonX64InterruptWindow:
        exit_reason_str = "X64InterruptWindow";
        break;
    case WHvRunVpExitReasonX64Halt:
        exit_reason_str = "X64Halt";
        break;
    case WHvRunVpExitReasonX64ApicEoi:
        exit_reason_str = "X64ApicEoi";
        break;
    case WHvRunVpExitReasonX64MsrAccess:
        exit_reason_str = "X64MsrAccess";
        break;
    case WHvRunVpExitReasonX64Cpuid:
        exit_reason_str = "X64Cpuid";
        break;
    case WHvRunVpExitReasonException:
        exit_reason_str = "Exception";
        break;
    case WHvRunVpExitReasonX64Rdtsc:
        exit_reason_str = "X64Rdtsc";
        break;
    case WHvRunVpExitReasonX64ApicSmiTrap:
        exit_reason_str = "X64ApicSmiTrap";
        break;
    case WHvRunVpExitReasonHypercall:
        exit_reason_str = "Hypercall";
        break;
    case WHvRunVpExitReasonX64ApicInitSipiTrap:
        exit_reason_str = "X64ApicInitSipiTrap";
        break;
    case WHvRunVpExitReasonX64ApicWriteTrap:
        exit_reason_str = "X64ApicWriteTrap";
        break;
    case WHvRunVpExitReasonCanceled:
        exit_reason_str = "Canceled";
        break;
    default:
        exit_reason_str = "?";
        break;
    }

#if defined(_M_X64)
    instance->config.debug_log(
        "[%u] %s(cs:rip=%04x:%p, efl=%08x) = %s",
        (unsigned)vcpu_index,
        exit_reason_str,
        exit_context->VpContext.Cs.Selector, exit_context->VpContext.Rip,
        (UINT32)exit_context->VpContext.Rflags,
        vm_result_error_string(result));
#endif
}
