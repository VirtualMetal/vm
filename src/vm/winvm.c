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
        is_terminated:1;                /* protected by thread_lock */
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

static DWORD WINAPI vm_thread(PVOID instance0);
static vm_result_t vm_vcpu_init(vm_t *instance, UINT32 vcpu_index);
static void vm_debug_log_mmap(vm_t *instance);
static void vm_debug_log_exit(vm_t *instance,
    UINT32 vcpu_index, WHV_RUN_VP_EXIT_CONTEXT *exit_context, vm_result_t result);

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
        result = vm_result(VM_ERROR_MEMORY, 0);
        goto exit;
    }

    memset(instance, 0, sizeof *instance);
    instance->config = *config;
    InitializeSRWLock(&instance->mmap_lock);
    list_init(&instance->mmap_list);
    InitializeSRWLock(&instance->thread_lock);

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
        result = vm_result(VM_ERROR_MEMORY, 0);
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
     * Cancel CPU #0, which will end its thread and cancel CPU #1, etc.
     */

    AcquireSRWLockExclusive(&instance->thread_lock);

    instance->is_terminated = 1;
    if (0 != instance->thread)
        WHvCancelRunVirtualProcessor(instance->partition, 0, 0);

    ReleaseSRWLockExclusive(&instance->thread_lock);

    return VM_RESULT_SUCCESS;
}

static DWORD WINAPI vm_thread(PVOID instance0)
{
    vm_result_t result;
    vm_t *instance = instance0;
    UINT32 vcpu_index;
    BOOL has_vcpu = FALSE;
    BOOL is_terminated, has_debug_log;
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
    ReleaseSRWLockExclusive(&instance->thread_lock);
    if (is_terminated)
    {
        result = vm_result(VM_ERROR_TERMINATED, 0);
        goto exit;
    }

    result = vm_vcpu_init(instance, vcpu_index);
    if (!vm_result_check(result))
        goto exit;

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

    has_debug_log = !!instance->config.debug_log;

    for (;;)
    {
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
            result = vm_result(VM_ERROR_TERMINATED, 0);
            break;

        case WHvRunVpExitReasonMemoryAccess:
            result = vm_result(VM_ERROR_TERMINATED, 0);
            break;

        case WHvRunVpExitReasonCanceled:
            result = vm_result(VM_ERROR_TERMINATED, 0);
            break;

        default:
            result = vm_result(VM_ERROR_TERMINATED, 0);
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

    WHvCancelRunVirtualProcessor(instance->partition, (vcpu_index + 1) % instance->config.vcpu_count, 0);

    if (0 != next_thread)
    {
        WaitForSingleObject(next_thread, INFINITE);
        CloseHandle(next_thread);
    }

    if (has_vcpu)
        WHvDeleteVirtualProcessor(instance->partition, vcpu_index);

    return 0;
}

static vm_result_t vm_vcpu_init(vm_t *instance, UINT32 vcpu_index)
{
#if defined(_M_X64)
#define CLR()                           regc = 0
#define REG(r)                          reg[regc] = WHvX64Register ## r, val[regc++]
#define VAL(...)                        (WHV_REGISTER_VALUE){ __VA_ARGS__ }

    vm_result_t result;
    void *page = 0;
    vm_count_t length;
    vm_count_t cpu_data_address;
    struct arch_x64_seg_desc seg_desc;
    struct arch_x64_sseg_desc sseg_desc;
    WHV_REGISTER_NAME reg[128];
    WHV_REGISTER_VALUE val[128];
    UINT32 regc;
    HRESULT hresult;

    page = malloc(sizeof(struct arch_x64_cpu_data));
    if (0 == page)
    {
        result = vm_result(VM_ERROR_MEMORY, 0);
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

    CLR();
    REG(Rax) = VAL(0);
    REG(Rcx) = VAL(0);
    REG(Rdx) = VAL(0);
    REG(Rbx) = VAL(0);
    REG(Rsp) = VAL(0);
    REG(Rbp) = VAL(0);
    REG(Rsi) = VAL(0);
    REG(Rdi) = VAL(0);
    REG(R8) = VAL(0);
    REG(R9) = VAL(0);
    REG(R10) = VAL(0);
    REG(R11) = VAL(0);
    REG(R12) = VAL(0);
    REG(R13) = VAL(0);
    REG(R14) = VAL(0);
    REG(R15) = VAL(0);
    REG(Rip) = VAL(.Reg64 = instance->config.vcpu_entry);
    REG(Rflags) = VAL(.Reg64 = 2);

    seg_desc = ((struct arch_x64_cpu_data *)page)->gdt.km_cs;
    REG(Cs) = VAL(
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
    REG(Ds) = VAL(
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
    REG(Es) = VAL(
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
    REG(Ss) = VAL(
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
    REG(Tr) = VAL(
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
    REG(Gdtr) = VAL(
        .Table.Base = cpu_data_address + (vm_count_t)&((struct arch_x64_cpu_data *)0)->gdt,
        .Table.Limit = sizeof(struct arch_x64_gdt));
    REG(Cr0) = VAL(.Reg64 = 0x80000011);    /* PG=1,MP=1,PE=1 */
    REG(Cr3) = VAL(.Reg64 = instance->config.page_table);
    REG(Cr4) = VAL(.Reg64 = 0x00000020);    /* PAE=1 */
    REG(Efer) = VAL(.Reg64 = 0x00000500);   /* LMA=1,LME=1 */

    hresult = WHvSetVirtualProcessorRegisters(instance->partition,
        vcpu_index, reg, regc, val);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_VCPU, hresult);
        goto exit;
    }

    result = VM_RESULT_SUCCESS;

exit:
    free(page);

    return result;

#undef CLR
#undef REG
#undef VAL
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
        "[%u] %s(cs:rip=%04x:%p, efl=%08x) = %d",
        (unsigned)vcpu_index,
        exit_reason_str,
        exit_context->VpContext.Cs.Selector, exit_context->VpContext.Rip,
        (UINT32)exit_context->VpContext.Rflags,
        (int)(vm_result_error(result) >> 48));
#endif
}
