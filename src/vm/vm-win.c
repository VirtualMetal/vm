/**
 * @file vm/vm-win.c
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
#include <winhvemulation.h>

#if defined(_M_X64)
#define VM_DEBUG_BP_INSTR               0xcc    /* INT3 instruction */
#define VM_DEBUG_BP_LENGTH              1
#endif

struct vm
{
    vm_config_t config;                 /* protected by thread_lock */
    WHV_PARTITION_HANDLE partition;
    WHV_EXTENDED_VM_EXITS extended_vm_exits;    /* immutable */
    SRWLOCK mmap_lock;
    list_link_t mmap_list;              /* protected by mmap_lock */
    SRWLOCK vm_start_lock;              /* vm_start/vm_wait serialization lock */
    unsigned
        has_vm_start:1,                 /* protected by vm_start_lock */
        has_vm_wait:1;                  /* protected by vm_start_lock */
    SRWLOCK thread_lock;
    HANDLE thread;                      /* protected by thread_lock */
    vm_count_t thread_count;
    vm_result_t thread_result;
    unsigned
        is_terminated:1,                /* protected by thread_lock */
        has_settable_whv_properties,    /* immutable */
        is_debuggable:1;                /* immutable */
    SRWLOCK vm_debug_lock;              /* vm_debug serialization lock */
    struct vm_debug *debug;             /* protected by thread_lock */
    vm_count_t debug_enable_count;      /* protected by thread_lock */
    SRWLOCK debug_server_lock;
    struct vm_debug_server *debug_server; /* protected by debug_server_lock */
};

struct vm_mmap
{
    list_link_t mmap_link;              /* protected by mmap_lock */
    PUINT8 file_alloc;
    PUINT8 head, tail;
    UINT64 head_length, tail_length;
    UINT64 guest_address;
    unsigned
        has_head:1,
        has_mapped_head:1,
        has_tail:1,
        has_mapped_tail:1;
};

struct vm_emulator_context
{
    vm_t *instance;
    UINT32 vcpu_index;
    vm_result_t result;
};

struct vm_debug
{
    vm_debug_events_t events;
    vm_debug_step_range_t step_range;
    CONDITION_VARIABLE stop_cvar, cont_cvar, wait_cvar;
        /* use condition variables for synchronization to streamline implementation across platforms */
    vm_count_t stop_cycle, stop_count, cont_cycle, cont_count;
    vm_count_t vcpu_index;
    vm_count_t bp_count;
    vm_count_t bp_ident[64];
    vm_count_t bp_paddr[64];
    UINT32 bp_value[64];
    unsigned
        is_debugged:1,
        is_stopped:1,
        is_continued:1,
        is_stepping:1,
        stop_on_start:1;
};

struct vm_debug_server
{
    HANDLE thread;                      /* protected by debug_server_lock; unsafe outside */
    SOCKET socket;                      /* safe outside debug_server_lock in vm_debug_server_thread */
    HANDLE event;                       /* ditto */
    HANDLE stop_event;                  /* ditto */
    LONG is_stopped;                    /* ditto */
};

struct vm_debug_socket
{
    vm_t *instance;
    struct vm_debug_server *debug_server;
    SOCKET socket;
    HANDLE event;
    SRWLOCK send_oob_lock;
    char send_oob_buffer[16];
    vm_count_t send_oob_length;
};

static vm_result_t vm_debug_internal(vm_t *instance,
    vm_count_t control, vm_count_t vcpu_index, vm_count_t address,
    void *buffer, vm_count_t *plength);
static int vm_debug_hasbp(vm_t *instance,
    vm_count_t vcpu_index, vm_count_t address);
static DWORD WINAPI vm_thread(PVOID instance0);
static vm_result_t vm_thread_debug_event(vm_t *instance, UINT32 vcpu_index);
static vm_result_t vm_thread_debug_exit(vm_t *instance, UINT32 vcpu_index,
    WHV_RUN_VP_EXIT_CONTEXT *exit_context, PBOOL phas_debug_event);
static vm_result_t vm_vcpu_init(vm_t *instance, UINT32 vcpu_index);
static vm_result_t vm_vcpu_cpuid_exit(vm_t *instance, UINT32 vcpu_index,
    WHV_RUN_VP_EXIT_CONTEXT *exit_context);
static vm_result_t vm_vcpu_debug(vm_t *instance, UINT32 vcpu_index, BOOL enable, BOOL step);
static vm_result_t vm_vcpu_debug_inject(vm_t *instance, UINT32 vcpu_index, UINT8 exception);
static vm_result_t vm_vcpu_getregs(vm_t *instance, UINT32 vcpu_index, void *buffer, vm_count_t *plength);
static vm_result_t vm_vcpu_setregs(vm_t *instance, UINT32 vcpu_index, void *buffer, vm_count_t *plength);
static vm_result_t vm_vcpu_translate(vm_t *instance, UINT32 vcpu_index,
    vm_count_t guest_virtual_address, vm_count_t *pguest_address);
static vm_result_t vm_default_infi(void *user_context, vm_count_t vcpu_index,
    int direction, vm_result_t result);
static vm_result_t vm_default_xmio(void *user_context, vm_count_t vcpu_index,
    vm_count_t flags, vm_count_t address, vm_count_t length, void *buffer);
static HRESULT CALLBACK vm_emulator_pmio(
    PVOID context,
    WHV_EMULATOR_IO_ACCESS_INFO *io);
static HRESULT CALLBACK vm_emulator_mmio(
    PVOID context,
    WHV_EMULATOR_MEMORY_ACCESS_INFO *mmio);
static HRESULT CALLBACK vm_emulator_getregs(
    PVOID context,
    const WHV_REGISTER_NAME *regn,
    UINT32 regc,
    WHV_REGISTER_VALUE *regv);
static HRESULT CALLBACK vm_emulator_setregs(
    PVOID context,
    const WHV_REGISTER_NAME *regn,
    UINT32 regc,
    const WHV_REGISTER_VALUE *regv);
static HRESULT CALLBACK vm_emulator_translate(
    PVOID context,
    WHV_GUEST_VIRTUAL_ADDRESS guest_virtual_address,
    WHV_TRANSLATE_GVA_FLAGS flags,
    WHV_TRANSLATE_GVA_RESULT_CODE *result,
    WHV_GUEST_PHYSICAL_ADDRESS *pguest_address);
static void vm_log_mmap(vm_t *instance);
static void vm_log_vcpu_exit(vm_t *instance,
    UINT32 vcpu_index, WHV_RUN_VP_EXIT_CONTEXT *exit_context, vm_result_t result);
static SOCKET vm_debug_server_listen(struct addrinfo *info, int ai_family);
static DWORD WINAPI vm_debug_server_thread(PVOID instance0);
static vm_result_t vm_debug_server_strm(void *socket0, int dir, void *buffer, vm_count_t *plength);

#if defined(_M_X64)
#define SIG_TO_REG(c0,c1,c2,c3)         ((c0) | ((c1) << 8) | ((c2) << 16) | ((c3) << 24))
static WHV_X64_CPUID_RESULT2 vm_vcpu_cpuid_results[] =
{
    { .Function = 1, .Output.Ecx = 0x80000000, .Mask.Ecx = 0x80000000 /* hypervisor present */},
    {
        .Function = 0x40000000,
        .Output.Eax = 0x40000001,
        .Output.Ebx = SIG_TO_REG('V','i','r','t'),
        .Output.Ecx = SIG_TO_REG('u','a','l','M'),
        .Output.Edx = SIG_TO_REG('e','t','a','l'),
        .Mask.Eax = 0xffffffff,
        .Mask.Ebx = 0xffffffff,
        .Mask.Ecx = 0xffffffff,
        .Mask.Edx = 0xffffffff,
    },
    {
        .Function = 0x40000001,
        .Output.Eax = 0,
        .Output.Ebx = 0,
        .Output.Ecx = 0,
        .Output.Edx = 0,
        .Mask.Eax = 0xffffffff,
        .Mask.Ebx = 0xffffffff,
        .Mask.Ecx = 0xffffffff,
        .Mask.Edx = 0xffffffff,
    }
};
#undef SIG_TO_REG
#endif

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
#define REGNAMX(r)                      regn[regc] = r, regc++
#define REGSETX(r)                      regn[regc] = r, regv[regc++]
#define REGVAL(...)                     (WHV_REGISTER_VALUE){ __VA_ARGS__ }
#define REGBIT(b)                       regb[regc - 1] = (b), regl += regb[regc - 1] >> 3
#endif

VM_API
vm_result_t vm_create(const vm_config_t *config, vm_t **pinstance)
{
    vm_result_t result;
    vm_t *instance = 0;
    vm_count_t vcpu_count;
    BOOL hypervisor_present;
    WHV_CAPABILITY_FEATURES features;
    WHV_EXTENDED_VM_EXITS extended_vm_exits;
    WHV_SYNTHETIC_PROCESSOR_FEATURES_BANKS synthetic_processor_features;
    UINT32 processor_count;
    UINT32 cpuid_exits[sizeof vm_vcpu_cpuid_results / sizeof vm_vcpu_cpuid_results[0]];
    UINT64 exception_exit_bitmap;
    WHV_X64_LOCAL_APIC_EMULATION_MODE lapic_mode;
    HRESULT hresult;

    *pinstance = 0;

    vcpu_count = config->vcpu_count;
    if (0 == vcpu_count)
    {
        DWORD_PTR process_mask, system_mask;
        if (!GetProcessAffinityMask(GetCurrentProcess(), &process_mask, &system_mask))
        {
            result = vm_result(VM_ERROR_HYPERVISOR, GetLastError());
            goto exit;
        }
        for (vcpu_count = 0; 0 != process_mask; process_mask >>= 1)
            vcpu_count += process_mask & 1;
    }
    if (0 == vcpu_count)
        vcpu_count = 1;
    else if (VM_CONFIG_VCPU_COUNT_MAX < vcpu_count)
        vcpu_count = VM_CONFIG_VCPU_COUNT_MAX;

    hresult = WHvGetCapability(
        WHvCapabilityCodeHypervisorPresent, &hypervisor_present, sizeof hypervisor_present, 0);
    if (FAILED(hresult) || !hypervisor_present)
    {
        result = vm_result(VM_ERROR_HYPERVISOR, hresult);
        goto exit;
    }

    hresult = WHvGetCapability(
        WHvCapabilityCodeFeatures, &features, sizeof features, 0);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_HYPERVISOR, hresult);
        goto exit;
    }
    if ((config->passthrough || config->vpic) && !features.LocalApicEmulation)
    {
        result = vm_result(VM_ERROR_HYPERVISOR, 0);
        goto exit;
    }

    hresult = WHvGetCapability(
        WHvCapabilityCodeExtendedVmExits, &extended_vm_exits, sizeof extended_vm_exits, 0);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_HYPERVISOR, hresult);
        goto exit;
    }

    if (config->passthrough)
    {
        hresult = WHvGetCapability(
            WHvCapabilityCodeSyntheticProcessorFeaturesBanks,
            &synthetic_processor_features, sizeof synthetic_processor_features, 0);
        if (FAILED(hresult))
        {
            result = vm_result(VM_ERROR_HYPERVISOR, hresult);
            goto exit;
        }
    }

    instance = malloc(sizeof *instance);
    if (0 == instance)
    {
        result = vm_result(VM_ERROR_RESOURCES, 0);
        goto exit;
    }

    memset(instance, 0, sizeof *instance);
    instance->config = *config;
    if (0 == instance->config.infi)
        instance->config.infi = vm_default_infi;
    if (0 == instance->config.xmio)
        instance->config.xmio = vm_default_xmio;
    instance->config.vcpu_count = vcpu_count;
    InitializeSRWLock(&instance->mmap_lock);
    list_init(&instance->mmap_list);
    InitializeSRWLock(&instance->vm_start_lock);
    InitializeSRWLock(&instance->thread_lock);
    InitializeSRWLock(&instance->vm_debug_lock);
    InitializeSRWLock(&instance->debug_server_lock);
#if defined(_M_X64)
    /*
     * According to the documentation WHvSetPartitionProperty works after
     * WHvSetupPartition (for specific properties) in builds 19H2 and above.
     *
     * The documentation for WHvGetCapability also states that X64RdtscExit
     * is supported in builds 19H2 and above. So abuse this bit to determine
     * if we are on 19H2 and above and can use WHvSetPartitionProperty after
     * WHvSetupPartition.
     */
    instance->has_settable_whv_properties = !!extended_vm_exits.X64RdtscExit;
#else
    instance->has_settable_whv_properties = 1;
#endif
    instance->is_debuggable = !!extended_vm_exits.ExceptionExit;

    hresult = WHvCreatePartition(&instance->partition);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_HYPERVISOR, hresult);
        goto exit;
    }

    processor_count = (UINT32)instance->config.vcpu_count;
    hresult = WHvSetPartitionProperty(instance->partition,
        WHvPartitionPropertyCodeProcessorCount, &processor_count, sizeof processor_count);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_HYPERVISOR, hresult);
        goto exit;
    }

    if (instance->config.passthrough || instance->config.vpic)
    {
        lapic_mode = WHvX64LocalApicEmulationModeXApic;
        hresult = WHvSetPartitionProperty(instance->partition,
            WHvPartitionPropertyCodeLocalApicEmulationMode,
            &lapic_mode, sizeof lapic_mode);
        if (FAILED(hresult))
        {
            result = vm_result(VM_ERROR_HYPERVISOR, hresult);
            goto exit;
        }
    }

    if (instance->config.passthrough)
    {
        hresult = WHvSetPartitionProperty(instance->partition,
            WHvPartitionPropertyCodeSyntheticProcessorFeaturesBanks,
            &synthetic_processor_features, sizeof synthetic_processor_features);
        if (FAILED(hresult))
        {
            result = vm_result(VM_ERROR_HYPERVISOR, hresult);
            goto exit;
        }
    }
    else
    {
#if defined(_M_X64)
        hresult = WHvSetPartitionProperty(instance->partition,
            WHvPartitionPropertyCodeCpuidResultList2, &vm_vcpu_cpuid_results, sizeof vm_vcpu_cpuid_results);
        if (FAILED(hresult))
        {
            if (WHV_E_UNKNOWN_PROPERTY != hresult)
            {
                result = vm_result(VM_ERROR_HYPERVISOR, hresult);
                goto exit;
            }

            /* CpuidResultList2 not supported: fall back to CpuidExit method */
            if (!extended_vm_exits.X64CpuidExit)
            {
                result = vm_result(VM_ERROR_HYPERVISOR, 0);
                goto exit;
            }

            for (vm_count_t i = 0; sizeof vm_vcpu_cpuid_results / sizeof vm_vcpu_cpuid_results[0] > i; i++)
                cpuid_exits[i] = vm_vcpu_cpuid_results[i].Function;

            hresult = WHvSetPartitionProperty(instance->partition,
                WHvPartitionPropertyCodeCpuidExitList, cpuid_exits, sizeof cpuid_exits);
            if (FAILED(hresult))
            {
                result = vm_result(VM_ERROR_HYPERVISOR, hresult);
                goto exit;
            }

            instance->extended_vm_exits.X64CpuidExit = 1;
        }
#endif
    }

    if (!instance->has_settable_whv_properties &&
        instance->is_debuggable &&
        (instance->config.compat_flags & VM_CONFIG_COMPAT_WHV_DEBUG))
        instance->extended_vm_exits.ExceptionExit = 1;

    if (0 != instance->extended_vm_exits.AsUINT64)
    {
        hresult = WHvSetPartitionProperty(instance->partition, WHvPartitionPropertyCodeExtendedVmExits,
            &instance->extended_vm_exits, sizeof instance->extended_vm_exits);
        if (FAILED(hresult))
        {
            result = vm_result(VM_ERROR_HYPERVISOR, hresult);
            goto exit;
        }
    }

    if (!instance->has_settable_whv_properties &&
        instance->is_debuggable &&
        (instance->config.compat_flags & VM_CONFIG_COMPAT_WHV_DEBUG))
    {
        exception_exit_bitmap =
            (1 << WHvX64ExceptionTypeDebugTrapOrFault) | (1 << WHvX64ExceptionTypeBreakpointTrap);
        hresult = WHvSetPartitionProperty(instance->partition,
            WHvPartitionPropertyCodeExceptionExitBitmap, &exception_exit_bitmap, sizeof exception_exit_bitmap);
        if (FAILED(hresult))
        {
            result = vm_result(VM_ERROR_HYPERVISOR, hresult);
            goto exit;
        }
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

VM_API
vm_result_t vm_delete(vm_t *instance)
{
    if (0 != instance->debug_server)
        vm_debug_server_stop(instance);

    while (!list_is_empty(&instance->mmap_list))
        vm_munmap(instance, (vm_mmap_t *)instance->mmap_list.next);

    if (0 != instance->partition)
        WHvDeletePartition(instance->partition);

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
    SYSTEM_INFO sys_info;
    BY_HANDLE_FILE_INFORMATION file_info;
    vm_count_t file_alloc_offset, file_end_offset, file_size;
    HANDLE mapping = 0;
    HRESULT hresult;

    *pmap = 0;

    GetSystemInfo(&sys_info);
    length = (length + sys_info.dwPageSize - 1) & ~(sys_info.dwPageSize - 1);

    if (0 != ((UINT_PTR)host_address & (sys_info.dwPageSize - 1)) ||
        0 != (file_offset & (sys_info.dwPageSize - 1)) ||
        0 != (guest_address & (sys_info.dwPageSize - 1)) ||
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
        if (!GetFileInformationByHandle((HANDLE)(UINT_PTR)file, &file_info))
        {
            result = vm_result(VM_ERROR_FILE, GetLastError());
            goto exit;
        }

        file_alloc_offset = file_offset & ~(sys_info.dwAllocationGranularity - 1);
        file_end_offset = file_offset + (0 != file_length ? file_length : length);
        file_size = ((UINT64)file_info.nFileSizeHigh << 32) | ((UINT64)file_info.nFileSizeLow);
        if (file_end_offset > file_size)
            file_end_offset = file_size;

        mapping = CreateFileMappingW((HANDLE)(UINT_PTR)file,
            0, PAGE_WRITECOPY, 0, 0, 0);
        if (0 == mapping)
        {
            result = vm_result(VM_ERROR_MEMORY, GetLastError());
            goto exit;
        }

        map->head_length = file_end_offset - file_offset;
        map->head_length = (map->head_length + sys_info.dwPageSize - 1) & ~(sys_info.dwPageSize - 1);
        map->file_alloc = MapViewOfFile(mapping, FILE_MAP_COPY,
            (DWORD)(file_alloc_offset >> 32), (DWORD)file_alloc_offset,
            file_end_offset - file_alloc_offset);
        if (0 == map->file_alloc)
        {
            result = vm_result(VM_ERROR_MEMORY, GetLastError());
            goto exit;
        }
        map->head = map->file_alloc + (file_offset - file_alloc_offset);
        map->has_head = 1;

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

VM_API
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
        VirtualFree(map->tail, 0, MEM_RELEASE);
    if (map->has_head)
        if (0 != map->file_alloc)
            UnmapViewOfFile(map->file_alloc);
        else
            VirtualFree(map->head, 0, MEM_RELEASE);

    free(map);

    return VM_RESULT_SUCCESS;
}

VM_API
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

VM_API
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

VM_API
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

VM_API
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

VM_API
vm_result_t vm_getconfig(vm_t *instance, vm_config_t *config, vm_count_t mask)
{
    AcquireSRWLockExclusive(&instance->thread_lock);

    if (~0ULL != mask)
    {
        for (vm_count_t index = 0; 0 != mask; mask >>= 1, index++)
            if (mask & 1)
                VM_CONFIG_FIELD(config, index) = VM_CONFIG_FIELD(&instance->config, index);
    }
    else
        memcpy(config, &instance->config, sizeof *config);

    ReleaseSRWLockExclusive(&instance->thread_lock);

    return VM_RESULT_SUCCESS;
}

VM_API
vm_result_t vm_setconfig(vm_t *instance, const vm_config_t *config, vm_count_t mask)
{
    vm_result_t result;

    if (!TryAcquireSRWLockExclusive(&instance->vm_start_lock))
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        return result;
    }

    if (instance->has_vm_start)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    AcquireSRWLockExclusive(&instance->thread_lock);

    mask &= VM_CONFIG_SETCONFIG_MASK;
    for (vm_count_t index = 0; 0 != mask; mask >>= 1, index++)
        if (mask & 1)
            VM_CONFIG_FIELD(&instance->config, index) = VM_CONFIG_FIELD(config, index);

    ReleaseSRWLockExclusive(&instance->thread_lock);

    result = VM_RESULT_SUCCESS;

exit:
    ReleaseSRWLockExclusive(&instance->vm_start_lock);

    return result;
}

VM_API
vm_result_t vm_start(vm_t *instance)
{
    vm_result_t result;

    if (!TryAcquireSRWLockExclusive(&instance->vm_start_lock))
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

    AcquireSRWLockExclusive(&instance->thread_lock);

    instance->thread_count = instance->config.vcpu_count;
    instance->thread = CreateThread(0, 0, vm_thread, instance, 0, 0);
    result = 0 != instance->thread ?
        VM_RESULT_SUCCESS : vm_result(VM_ERROR_VCPU, GetLastError());
    if (vm_result_check(result))
        instance->has_vm_start = 1;

    ReleaseSRWLockExclusive(&instance->thread_lock);

exit:
    ReleaseSRWLockExclusive(&instance->vm_start_lock);

    return result;
}

VM_API
vm_result_t vm_wait(vm_t *instance)
{
    vm_result_t result;

    AcquireSRWLockExclusive(&instance->vm_start_lock);

    if (!instance->has_vm_start)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }
    if (instance->has_vm_wait)
        goto getres;

    /*
     * The functions vm_start and vm_wait may read instance->thread when inside the
     * vm_start_lock, even when outside the thread_lock.
     *
     * This works because vm_start and vm_wait are the only writers of instance->thread
     * and because instance->thread is only ever written when inside both the vm_start_lock
     * and thread_lock. This excludes readers of instance->thread inside the vm_start_lock
     * (i.e. vm_start and vm_wait) or readers of instance->thread inside the thread_lock
     * only (i.e. functions other than vm_start and vm_wait).
     */
    WaitForSingleObject(instance->thread, INFINITE);

    AcquireSRWLockExclusive(&instance->thread_lock);

    CloseHandle(instance->thread);
    instance->thread = 0;
    instance->has_vm_wait = 1;

    ReleaseSRWLockExclusive(&instance->thread_lock);

getres:
    result = InterlockedCompareExchange64(&instance->thread_result, ~0LL, ~0LL);
    if (VM_ERROR_TERMINATED == vm_result_error(result))
        result = VM_RESULT_SUCCESS;

exit:
    ReleaseSRWLockExclusive(&instance->vm_start_lock);

    return result;
}

VM_API
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

VM_API
vm_result_t vm_debug(vm_t *instance,
    vm_count_t control, vm_count_t vcpu_index, vm_count_t address,
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

    result = vm_debug_internal(instance, control, vcpu_index, address, buffer, plength);

exit:
    ReleaseSRWLockExclusive(&instance->thread_lock);
    ReleaseSRWLockExclusive(&instance->vm_debug_lock);

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
        InitializeConditionVariable(&debug->stop_cvar);
        InitializeConditionVariable(&debug->cont_cvar);
        InitializeConditionVariable(&debug->wait_cvar);
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

        debug->events = (vm_debug_events_t){ 0 };

        for (vm_count_t index = debug->bp_count - 1; debug->bp_count > index; index--)
            vm_debug_internal(instance, VM_DEBUG_DELBP, ~0ULL, debug->bp_paddr[index], 0, 0);

        debug->is_debugged = 0;
        vm_debug_internal(instance, VM_DEBUG_CONT, 0, 0, 0, 0);

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
        if (0 != instance->thread)
        {
            if (VM_DEBUG_BREAK == control)
            {
                for (UINT32 index = 0; instance->config.vcpu_count > index; index++)
                    WHvCancelRunVirtualProcessor(instance->partition, index, 0);
            }
            while (!instance->is_terminated &&
                !debug->is_stopped)
                SleepConditionVariableSRW(&debug->stop_cvar, &instance->thread_lock, INFINITE, 0);
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
        if (0 != instance->thread)
        {
            debug->is_continued = 1;
            debug->vcpu_index = vcpu_index;
            debug->is_stepping = VM_DEBUG_STEP == control;
            debug->step_range = VM_DEBUG_STEP == control && 0 != plength ?
                *(vm_debug_step_range_t *)buffer :
                (vm_debug_step_range_t){ 0 };
            WakeAllConditionVariable(&debug->wait_cvar);
            while (!instance->is_terminated &&
                debug->is_continued)
                SleepConditionVariableSRW(&debug->cont_cvar, &instance->thread_lock, INFINITE, 0);
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
                result = vm_vcpu_translate(instance, (UINT32)vcpu_index, address, &guest_address);
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
            UINT32 bp_value = 0, bp_instr = VM_DEBUG_BP_INSTR;
            vm_count_t bp_length, bp_expected = VM_DEBUG_BP_LENGTH;

            bp_ident = bp_paddr = address;

            if (VM_DEBUG_SETBP == control && ~0ULL != vcpu_index)
            {
                result = vm_vcpu_translate(instance, (UINT32)vcpu_index, address, &bp_paddr);
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

    result = vm_vcpu_translate(instance, (UINT32)vcpu_index, address, &bp_paddr);
    if (!vm_result_check(result))
        return 0;

    for (index = 0; debug->bp_count > index; index++)
        if (debug->bp_paddr[index] == bp_paddr)
            return 1;

    return 0;
}

static DWORD WINAPI vm_thread(PVOID instance0)
{
    static WHV_EMULATOR_CALLBACKS emulator_callbacks =
    {
        .Size = sizeof(WHV_EMULATOR_CALLBACKS),
        .WHvEmulatorIoPortCallback = vm_emulator_pmio,
        .WHvEmulatorMemoryCallback = vm_emulator_mmio,
        .WHvEmulatorGetVirtualProcessorRegisters = vm_emulator_getregs,
        .WHvEmulatorSetVirtualProcessorRegisters = vm_emulator_setregs,
        .WHvEmulatorTranslateGvaPage = vm_emulator_translate,
    };
    vm_result_t result;
    vm_t *instance = instance0;
    WHV_EMULATOR_HANDLE emulator = 0;
    WHV_EMULATOR_STATUS emulator_status;
    struct vm_emulator_context emulator_context;
    UINT32 vcpu_index;
    BOOL has_infi = FALSE, has_vcpu = FALSE;
    BOOL is_terminated, has_debug_event, has_debug_log;
    HANDLE next_thread = 0;
    WHV_RUN_VP_EXIT_CONTEXT exit_context;
    HRESULT hresult;

    vcpu_index = (UINT32)(instance->config.vcpu_count - instance->thread_count);

    result = instance->config.infi(instance->config.user_context, vcpu_index, +1, VM_RESULT_SUCCESS);
    if (!vm_result_check(result))
        goto exit;
    has_infi = TRUE;

    hresult = WHvEmulatorCreateEmulator(&emulator_callbacks, &emulator);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_VCPU, hresult);
        goto exit;
    }

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

    emulator_context.instance = instance;
    emulator_context.vcpu_index = vcpu_index;

    has_debug_log = !!instance->config.logf &&
        0 != (instance->config.log_flags & VM_CONFIG_LOG_HYPERVISOR);

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
            hresult = WHvEmulatorTryIoEmulation(emulator, &emulator_context,
                &exit_context.VpContext, &exit_context.IoPortAccess,
                &emulator_status);
            if (FAILED(hresult))
            {
                result = vm_result(VM_ERROR_VCPU, hresult);
                goto exit;
            }
            else if (!emulator_status.EmulationSuccessful)
            {
                result = emulator_status.IoPortCallbackFailed ?
                    emulator_context.result : vm_result(VM_ERROR_VCPU, 0);
                goto exit;
            }
            break;

        case WHvRunVpExitReasonMemoryAccess:
            hresult = WHvEmulatorTryMmioEmulation(emulator, &emulator_context,
                &exit_context.VpContext, &exit_context.MemoryAccess,
                &emulator_status);
            if (FAILED(hresult))
            {
                result = vm_result(VM_ERROR_VCPU, hresult);
                goto exit;
            }
            else if (!emulator_status.EmulationSuccessful)
            {
                result = emulator_status.MemoryCallbackFailed ?
                    emulator_context.result : vm_result(VM_ERROR_VCPU, 0);
                goto exit;
            }
            break;

#if defined(_M_X64)
        case WHvRunVpExitReasonX64Cpuid:
            result = vm_vcpu_cpuid_exit(instance, vcpu_index, &exit_context);
            break;
#endif

        case WHvRunVpExitReasonException:
            result = vm_thread_debug_exit(instance, vcpu_index, &exit_context, &has_debug_event);
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
            vm_log_vcpu_exit(instance, vcpu_index, &exit_context, result);
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

    if (0 != emulator)
        WHvEmulatorDestroyEmulator(emulator);

    if (has_infi)
        instance->config.infi(instance->config.user_context, vcpu_index, -1, result);

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

    for (;;)
    {
        struct vm_debug *debug;
        BOOL is_terminated = FALSE, is_debugged = FALSE, is_stepping = FALSE, other_is_stepping = FALSE;
        vm_count_t stop_cycle, cont_cycle;

        AcquireSRWLockExclusive(&instance->thread_lock);

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
            WakeAllConditionVariable(&debug->stop_cvar);
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
            WakeAllConditionVariable(&debug->cont_cvar);
        }

        is_debugged = debug->is_debugged;
        is_stepping = is_debugged && debug->is_stepping && vcpu_index == debug->vcpu_index;
        other_is_stepping = is_debugged && debug->is_stepping && vcpu_index != debug->vcpu_index;

    skip_debug_event:
        is_terminated = instance->is_terminated;
        ReleaseSRWLockExclusive(&instance->thread_lock);

        if (is_terminated)
            return vm_result(VM_ERROR_TERMINATED, 0);

        if (other_is_stepping)
            continue;

        return vm_vcpu_debug(instance, vcpu_index, is_debugged, is_stepping);
    }

#undef WAITCOND
}

static vm_result_t vm_thread_debug_exit(vm_t *instance, UINT32 vcpu_index,
    WHV_RUN_VP_EXIT_CONTEXT *exit_context, PBOOL phas_debug_event)
{
    vm_result_t result;
    struct vm_debug *debug;
    BOOL has_debug_event, range_step;
    UINT8 inject;

    *phas_debug_event = FALSE;

#if defined(_M_X64)
    vm_count_t pc = exit_context->VpContext.Rip;
    BOOL is_db_ex = WHvX64ExceptionTypeDebugTrapOrFault == exit_context->VpException.ExceptionType;
    BOOL is_bp_ex = WHvX64ExceptionTypeBreakpointTrap == exit_context->VpException.ExceptionType;
    if (!is_db_ex && !is_bp_ex)
#endif
    {
        result = vm_result(VM_ERROR_VCPU, 0);
        goto exit;
    }

    AcquireSRWLockExclusive(&instance->thread_lock);

    has_debug_event = range_step = FALSE;
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
            inject = WHvX64ExceptionTypeDebugTrapOrFault;
    }
    else if (is_bp_ex)
    {
        if (0 != (debug = instance->debug) && debug->is_debugged &&
            vm_debug_hasbp(instance, vcpu_index, pc))
        {
            for (UINT32 index = 0; instance->config.vcpu_count > index; index++)
                if (index != vcpu_index)
                    WHvCancelRunVirtualProcessor(instance->partition, index, 0);
            has_debug_event = TRUE;
            debug->stop_on_start = 1;
        }
        else
            inject = WHvX64ExceptionTypeBreakpointTrap;
    }

    ReleaseSRWLockExclusive(&instance->thread_lock);

    if (inject)
    {
        /*
         * If we are reinjecting do not report a debug event (has_debug_event == FALSE).
         */
        result = vm_vcpu_debug_inject(instance, vcpu_index, inject);
        if (!vm_result_check(result))
            goto exit;
    }
    else if (range_step)
    {
        /*
         * If we are range stepping do not report a debug event (has_debug_event == FALSE).
         * Instead prepare the virtual CPU for another single step through the step range.
         */
        result = vm_vcpu_debug(instance, vcpu_index, TRUE, TRUE);
        if (!vm_result_check(result))
            goto exit;
    }

    *phas_debug_event = has_debug_event;
    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

static vm_result_t vm_vcpu_init(vm_t *instance, UINT32 vcpu_index)
{
#if defined(_M_X64)
    vm_result_t result;
    void *page = 0;
    vm_count_t vcpu_table, stride, length, cpu_data_address;
    vm_count_t vcpu_entry, vcpu_args[6];
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

    regc = 0;
    REGSET(Rax) = REGVAL(0);
    REGSET(Rcx) = REGVAL(vcpu_args[3]);
    REGSET(Rdx) = REGVAL(vcpu_args[2]);
    REGSET(Rbx) = REGVAL(0);
    REGSET(Rsp) = REGVAL(0);
    REGSET(Rbp) = REGVAL(0);
    REGSET(Rsi) = REGVAL(vcpu_args[1]);
    REGSET(Rdi) = REGVAL(vcpu_args[0]);
    REGSET(R8) = REGVAL(vcpu_args[4]);
    REGSET(R9) = REGVAL(vcpu_args[5]);
    REGSET(R10) = REGVAL(0);
    REGSET(R11) = REGVAL(0);
    REGSET(R12) = REGVAL(0);
    REGSET(R13) = REGVAL(0);
    REGSET(R14) = REGVAL(0);
    REGSET(R15) = REGVAL(0);
    REGSET(Rip) = REGVAL(.Reg64 = vcpu_entry);
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
    REGSET(Idtr) = REGVAL(
        .Table.Base = instance->config.vcpu_alt_table,
        .Table.Limit = 0 != instance->config.vcpu_alt_table ? sizeof(struct arch_x64_idt) : 0);
    REGSET(Cr0) = REGVAL(.Reg64 = 0x80000011);    /* PG=1,MP=1,PE=1 */
    REGSET(Cr3) = REGVAL(.Reg64 = instance->config.page_table);
    REGSET(Cr4) = REGVAL(.Reg64 = 0x00000020);    /* PAE=1 */
    REGSET(Efer) = REGVAL(.Reg64 = 0x00000500);   /* LMA=1,LME=1 */

    if (0 != vcpu_index && 0 != instance->config.vcpu_mailbox)
        /* make sure that VCPU is runnable regardless if it is a boot or application one */
        REGSETX(WHvRegisterInternalActivityState) = REGVAL(.InternalActivity = { 0 });

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


static vm_result_t vm_vcpu_cpuid_exit(vm_t *instance, UINT32 vcpu_index,
    WHV_RUN_VP_EXIT_CONTEXT *exit_context)
{
#if defined(_M_X64)
    vm_result_t result;
    WHV_REGISTER_NAME regn[128];
    WHV_REGISTER_VALUE regv[128];
    UINT32 regc;
    HRESULT hresult;

    for (vm_count_t i = 0; sizeof vm_vcpu_cpuid_results / sizeof vm_vcpu_cpuid_results[0] > i; i++)
        if (exit_context->CpuidAccess.Rax == vm_vcpu_cpuid_results[i].Function)
        {
            exit_context->CpuidAccess.DefaultResultRax &= ~vm_vcpu_cpuid_results[i].Mask.Eax;
            exit_context->CpuidAccess.DefaultResultRax |= vm_vcpu_cpuid_results[i].Output.Eax;

            exit_context->CpuidAccess.DefaultResultRbx &= ~vm_vcpu_cpuid_results[i].Mask.Ebx;
            exit_context->CpuidAccess.DefaultResultRbx |= vm_vcpu_cpuid_results[i].Output.Ebx;

            exit_context->CpuidAccess.DefaultResultRcx &= ~vm_vcpu_cpuid_results[i].Mask.Ecx;
            exit_context->CpuidAccess.DefaultResultRcx |= vm_vcpu_cpuid_results[i].Output.Ecx;

            exit_context->CpuidAccess.DefaultResultRdx &= ~vm_vcpu_cpuid_results[i].Mask.Edx;
            exit_context->CpuidAccess.DefaultResultRdx |= vm_vcpu_cpuid_results[i].Output.Edx;
        }

    regc = 0;
    REGSET(Rax) = REGVAL(exit_context->CpuidAccess.DefaultResultRax);
    REGSET(Rbx) = REGVAL(exit_context->CpuidAccess.DefaultResultRbx);
    REGSET(Rcx) = REGVAL(exit_context->CpuidAccess.DefaultResultRcx);
    REGSET(Rdx) = REGVAL(exit_context->CpuidAccess.DefaultResultRdx);
    REGSET(Rip) = REGVAL(exit_context->VpContext.Rip + exit_context->VpContext.InstructionLength);

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

static vm_result_t vm_vcpu_debug(vm_t *instance, UINT32 vcpu_index, BOOL enable, BOOL step)
{
#if defined(_M_X64)
    vm_result_t result;
    WHV_EXTENDED_VM_EXITS extended_vm_exits;
    UINT64 exception_exit_bitmap;
    WHV_REGISTER_NAME regn[1];
    WHV_REGISTER_VALUE regv[1];
    UINT32 regc;
    UINT64 rflags;
    HRESULT hresult;

    if (instance->has_settable_whv_properties)
    {
        AcquireSRWLockExclusive(&instance->thread_lock);
        if (( enable && 0 == instance->debug_enable_count++) ||
            (!enable && 1 == instance->debug_enable_count--))
        {
            extended_vm_exits = instance->extended_vm_exits;
            extended_vm_exits.ExceptionExit = !!enable;
            hresult = WHvSetPartitionProperty(instance->partition,
                WHvPartitionPropertyCodeExtendedVmExits, &extended_vm_exits, sizeof extended_vm_exits);
            if (FAILED(hresult))
            {
                ReleaseSRWLockExclusive(&instance->thread_lock);
                result = vm_result(VM_ERROR_HYPERVISOR, hresult);
                goto exit;
            }

            exception_exit_bitmap = enable ?
                (1 << WHvX64ExceptionTypeDebugTrapOrFault) | (1 << WHvX64ExceptionTypeBreakpointTrap) :
                0;
            hresult = WHvSetPartitionProperty(instance->partition,
                WHvPartitionPropertyCodeExceptionExitBitmap, &exception_exit_bitmap, sizeof exception_exit_bitmap);
            if (FAILED(hresult))
            {
                ReleaseSRWLockExclusive(&instance->thread_lock);
                result = vm_result(VM_ERROR_HYPERVISOR, hresult);
                goto exit;
            }
        }
        ReleaseSRWLockExclusive(&instance->thread_lock);
    }

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

static vm_result_t vm_vcpu_debug_inject(vm_t *instance, UINT32 vcpu_index, UINT8 exception)
{
#if defined(_M_X64)
    vm_result_t result;
    WHV_REGISTER_NAME regn[1];
    WHV_REGISTER_VALUE regv[1];
    UINT32 regc;
    HRESULT hresult;

    switch (exception)
    {
    case WHvX64ExceptionTypeDebugTrapOrFault:
        regc = 1;
        regn[0] = WHvRegisterPendingInterruption;
        regv[0] = REGVAL
        (
            .PendingInterruption.InterruptionPending = 1,
            .PendingInterruption.InterruptionType = WHvX64PendingException,
            .PendingInterruption.InterruptionVector = WHvX64ExceptionTypeDebugTrapOrFault,
        );
        break;
    case WHvX64ExceptionTypeBreakpointTrap:
        /*
         * We seem to have a bit of a confusion regarding #BP injection:
         *
         * - Intel manual (vol 3 - 25.8.3) says we should use type 6: Software exception.
         *     - Intel manual (vol 3 - 27.6.1.1) also suggests that type 4: Software Interrupt
         *       should work. Software interrupts and software exceptions appear to work in a
         *       similar fashion, except in virtual-8086 mode which we do not use.
         * - AMD manual (vol 2 - 15.20) says we should use type 3: Exception (fault or trap).
         * - Hyper-V seems to only like Type==4 && Length == 1, at least on this Intel machine.
         *   (Is it possible that we need Type==3 && Length == 0 on an AMD machine?)
         *
         * Stick with what WORKS ON MY MACHINE.
         */
        regc = 1;
        regn[0] = WHvRegisterPendingInterruption;
        regv[0] = REGVAL
        (
            .PendingInterruption.InterruptionPending = 1,
            .PendingInterruption.InterruptionType = 4,  /* Software interrupt */
            .PendingInterruption.InterruptionVector = WHvX64ExceptionTypeBreakpointTrap,
            .PendingInterruption.InstructionLength = 1,
        );
        break;
    default:
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

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

static vm_result_t vm_vcpu_translate(vm_t *instance, UINT32 vcpu_index,
    vm_count_t guest_virtual_address, vm_count_t *pguest_address)
{
    vm_result_t result;
    vm_count_t guest_address;
    WHV_TRANSLATE_GVA_RESULT translation;
    HRESULT hresult;

    *pguest_address = 0;

    hresult = WHvTranslateGva(instance->partition,
        (UINT32)vcpu_index, guest_virtual_address,
        WHvTranslateGvaFlagPrivilegeExempt | WHvTranslateGvaFlagValidateRead,
        &translation, &guest_address);
    if (FAILED(hresult))
    {
        result = vm_result(VM_ERROR_VCPU, hresult);
        goto exit;
    }
    if (WHvTranslateGvaResultSuccess != translation.ResultCode)
    {
        result = vm_result(VM_ERROR_MEMORY, 0);
        goto exit;
    }

    *pguest_address = guest_address;
    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

static vm_result_t vm_default_infi(void *user_context, vm_count_t vcpu_index,
    int direction, vm_result_t result)
{
    return VM_RESULT_SUCCESS;
}

static vm_result_t vm_default_xmio(void *user_context, vm_count_t vcpu_index,
    vm_count_t flags, vm_count_t address, vm_count_t length, void *buffer)
{
    return vm_result(VM_ERROR_VCPU, 0);
}

static HRESULT CALLBACK vm_emulator_pmio(
    PVOID context0,
    WHV_EMULATOR_IO_ACCESS_INFO *io)
{
    struct vm_emulator_context *context = context0;
    vm_t *instance = context->instance;
    context->result = instance->config.xmio(instance->config.user_context, context->vcpu_index,
        VM_XMIO_PMIO | io->Direction, io->Port, io->AccessSize, &io->Data);
    return vm_result_check(context->result) ? S_OK : E_FAIL;
}

static HRESULT CALLBACK vm_emulator_mmio(
    PVOID context0,
    WHV_EMULATOR_MEMORY_ACCESS_INFO *mmio)
{
    struct vm_emulator_context *context = context0;
    vm_t *instance = context->instance;
    context->result = instance->config.xmio(instance->config.user_context, context->vcpu_index,
        VM_XMIO_MMIO | mmio->Direction, mmio->GpaAddress, mmio->AccessSize, &mmio->Data);
    return vm_result_check(context->result) ? S_OK : E_FAIL;
}

static HRESULT CALLBACK vm_emulator_getregs(
    PVOID context0,
    const WHV_REGISTER_NAME *regn,
    UINT32 regc,
    WHV_REGISTER_VALUE *regv)
{
    struct vm_emulator_context *context = context0;
    vm_t *instance = context->instance;
    return WHvGetVirtualProcessorRegisters(instance->partition,
        context->vcpu_index, regn, regc, regv);
}

static HRESULT CALLBACK vm_emulator_setregs(
    PVOID context0,
    const WHV_REGISTER_NAME *regn,
    UINT32 regc,
    const WHV_REGISTER_VALUE *regv)
{
    struct vm_emulator_context *context = context0;
    vm_t *instance = context->instance;
    return WHvSetVirtualProcessorRegisters(instance->partition,
        context->vcpu_index, regn, regc, regv);
}

static HRESULT CALLBACK vm_emulator_translate(
    PVOID context0,
    WHV_GUEST_VIRTUAL_ADDRESS guest_virtual_address,
    WHV_TRANSLATE_GVA_FLAGS flags,
    WHV_TRANSLATE_GVA_RESULT_CODE *result,
    WHV_GUEST_PHYSICAL_ADDRESS *pguest_address)
{
    struct vm_emulator_context *context = context0;
    vm_t *instance = context->instance;
    WHV_TRANSLATE_GVA_RESULT translation;
    HRESULT hresult;
    hresult = WHvTranslateGva(instance->partition,
        context->vcpu_index, guest_virtual_address, flags, &translation, pguest_address);
    if (FAILED(hresult))
        return hresult;
    *result = translation.ResultCode;
    return hresult;
}

static void vm_log_mmap(vm_t *instance)
{
    AcquireSRWLockExclusive(&instance->mmap_lock);

    list_traverse(link, prev, &instance->mmap_list)
    {
        vm_mmap_t *map = (vm_mmap_t *)link;
        UINT64 length, end_address;
        char pathbuf[1024], *path = 0;

        if (0 != map->file_alloc)
            if (0 != GetMappedFileNameA(GetCurrentProcess(), map->file_alloc, pathbuf, sizeof pathbuf))
            {
                path = pathbuf;
                for (char *p = pathbuf; *p; p++)
                    if ('\\' == *p)
                        path = p + 1;
            }

        length = map->head_length + map->tail_length;
        end_address = map->guest_address + length - 1;
        instance->config.logf("mmap %08x%08x-%08x%08x %7uK%s%s",
            (UINT32)(map->guest_address >> 32), (UINT32)map->guest_address,
            (UINT32)(end_address >> 32), (UINT32)end_address,
            (UINT32)(length >> 10),
            path ? " " : "", path ? path : "");
    }

    ReleaseSRWLockExclusive(&instance->mmap_lock);
}

static void vm_log_vcpu_exit(vm_t *instance,
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
    instance->config.logf(
        "[%u] %s(cs:rip=%04x:%p, efl=%08x) = %s",
        (unsigned)vcpu_index,
        exit_reason_str,
        exit_context->VpContext.Cs.Selector, exit_context->VpContext.Rip,
        (UINT32)exit_context->VpContext.Rflags,
        vm_result_error_string(result));
#endif
}

VM_API
vm_result_t vm_debug_server_start(vm_t *instance,
    const char *hostname, const char *servname)
{
    vm_result_t result;
    WSADATA wsa_data;
    int wsa_res, gai_err;
    BOOL has_wsa = FALSE;
    struct addrinfo hint, *info = 0;
    struct vm_debug_server *debug_server = 0;

    AcquireSRWLockExclusive(&instance->debug_server_lock);

    if (0 == servname || 0 != instance->debug_server)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    wsa_res = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (0 != wsa_res)
    {
        result = vm_result(VM_ERROR_NETWORK, wsa_res);
        goto exit;
    }
    has_wsa = TRUE;

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
    debug_server->socket = INVALID_SOCKET;
    debug_server->event = WSACreateEvent();
    debug_server->stop_event = CreateEvent(0, FALSE, FALSE, 0);
    if (WSA_INVALID_EVENT == debug_server->event ||
        WSA_INVALID_EVENT == debug_server->stop_event)
    {
        result = vm_result(VM_ERROR_RESOURCES, WSAGetLastError());
        goto exit;
    }

    debug_server->socket = vm_debug_server_listen(info, AF_INET6);
    if (INVALID_SOCKET == debug_server->socket)
        debug_server->socket = vm_debug_server_listen(info, AF_INET);
    if (INVALID_SOCKET == debug_server->socket)
    {
        result = vm_result(VM_ERROR_NETWORK, WSAGetLastError());
        goto exit;
    }

    instance->debug_server = debug_server;

    debug_server->thread = CreateThread(0, 0, vm_debug_server_thread, instance, 0, 0);
    if (0 == debug_server->thread)
    {
        instance->debug_server = 0;
        result = vm_result(VM_ERROR_NETWORK, GetLastError());
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
        if (INVALID_SOCKET != debug_server->socket)
            closesocket(debug_server->socket);
        if (WSA_INVALID_EVENT != debug_server->event)
            WSACloseEvent(debug_server->event);
        if (WSA_INVALID_EVENT != debug_server->stop_event)
            WSACloseEvent(debug_server->stop_event);
        free(debug_server);
    }

    if (!vm_result_check(result) && has_wsa)
        WSACleanup();

    ReleaseSRWLockExclusive(&instance->debug_server_lock);

    return result;
}

VM_API
vm_result_t vm_debug_server_stop(vm_t *instance)
{
    vm_result_t result;
    struct vm_debug_server *debug_server = 0;

    AcquireSRWLockExclusive(&instance->debug_server_lock);

    if (0 == (debug_server = instance->debug_server))
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    InterlockedExchange(&debug_server->is_stopped, 1);
    WSASetEvent(debug_server->stop_event);
    WaitForSingleObject(debug_server->thread, INFINITE);

    CloseHandle(debug_server->thread);
    if (INVALID_SOCKET != debug_server->socket)
        closesocket(debug_server->socket);
    if (WSA_INVALID_EVENT != debug_server->event)
        WSACloseEvent(debug_server->event);
    if (WSA_INVALID_EVENT != debug_server->stop_event)
        WSACloseEvent(debug_server->stop_event);
    free(debug_server);

    WSACleanup();

    instance->debug_server = 0;

    result = VM_RESULT_SUCCESS;

exit:
    ReleaseSRWLockExclusive(&instance->debug_server_lock);

    return result;
}

static SOCKET vm_debug_server_listen(struct addrinfo *info, int ai_family)
{
    int error = 0;
    for (struct addrinfo *p = info; p; p = p->ai_next)
        if (ai_family == p->ai_family)
        {
            SOCKET sock;
            int v6only = 0; /* dual stack socket */
            int reuse = 1;  /* reuse address */
            if (INVALID_SOCKET == (sock = WSASocketW(p->ai_family, p->ai_socktype, p->ai_protocol,
                    0, 0, WSA_FLAG_NO_HANDLE_INHERIT)) ||
                (AF_INET6 == p->ai_family && SOCKET_ERROR == setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
                    (void *)&v6only, sizeof v6only)) ||
                SOCKET_ERROR == setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                    (void *)&reuse, sizeof reuse) ||
                SOCKET_ERROR == bind(sock, p->ai_addr, (int)p->ai_addrlen) ||
                SOCKET_ERROR == listen(sock, 1))
            {
                if (0 == error)
                    error = WSAGetLastError();
                if (INVALID_SOCKET != sock)
                    closesocket(sock);
                continue;
            }
            return sock;
        }
    WSASetLastError(error);
    return INVALID_SOCKET;
}

static inline
BOOL vm_debug_server_poll(struct vm_debug_server *debug_server,
    SOCKET socket, HANDLE event, long netevents)
{
    if (InterlockedCompareExchange(&debug_server->is_stopped, ~0L, ~0L))
        return FALSE;
    HANDLE events[2] = { debug_server->stop_event, event };
    WSANETWORKEVENTS wsaevents;
    WSAEventSelect(socket, event, netevents);
    WSAWaitForMultipleEvents(2, events, FALSE, INFINITE, FALSE);
    WSAEnumNetworkEvents(socket, event, &wsaevents);
    return !InterlockedCompareExchange(&debug_server->is_stopped, ~0L, ~0L);
}

static DWORD WINAPI vm_debug_server_thread(PVOID instance0)
{
    vm_result_t result;
    vm_t *instance = instance0;
    struct vm_debug_socket debug_socket_buf, *debug_socket = &debug_socket_buf;
    struct vm_debug_server *debug_server;

    /*
     * It is safe to access instance->debug_server outside the debug_server_lock,
     * because our lifetime is controlled by debug_server_start / debug_server_stop
     * which do access instance->debug_server inside the debug_server_lock.
     */
    debug_server = instance->debug_server;

    while (vm_debug_server_poll(debug_server,
        debug_server->socket, debug_server->event, FD_ACCEPT))
    {
        memset(debug_socket, 0, sizeof *debug_socket);
        debug_socket->instance = instance;
        debug_socket->debug_server = debug_server;

        debug_socket->socket = accept(debug_server->socket, 0, 0);
        if (INVALID_SOCKET == debug_socket->socket)
        {
            switch (WSAGetLastError())
            {
            case WSAEWOULDBLOCK:
                continue;
            case WSAECONNRESET:
            case WSAENETDOWN:
                /* retry on transient errors */
                continue;
            }
            result = vm_result(VM_ERROR_NETWORK, WSAGetLastError());
            goto exit;
        }

        result = VM_RESULT_SUCCESS;

        InitializeSRWLock(&debug_socket->send_oob_lock);
        debug_socket->send_oob_length = 0;

        debug_socket->event = WSACreateEvent();
        if (WSA_INVALID_EVENT == debug_socket->event)
            goto loop_bottom;
        WSAEventSelect(debug_socket->socket, debug_socket->event, 0);
            /* cancel association of listening socket's event with our socket */

        int nodelay = 1;
        setsockopt(debug_socket->socket, IPPROTO_TCP, TCP_NODELAY, (void *)&nodelay, sizeof nodelay);

        result = vm_gdb(instance, vm_debug_server_strm, debug_socket);

    loop_bottom:
        closesocket(debug_socket->socket);
        if (WSA_INVALID_EVENT != debug_socket->event)
            WSACloseEvent(debug_socket->event);

        if (VM_ERROR_TERMINATED == vm_result_error(result))
            break;
    }

exit:
    (void)result;
    return 0;
}

static vm_result_t vm_debug_server_strm(void *socket0, int dir, void *buffer, vm_count_t *plength)
{
    vm_result_t result;
    struct vm_debug_socket *debug_socket = (struct vm_debug_socket *)socket0;
    struct vm_debug_server *debug_server = debug_socket->debug_server;
    int length, tbytes, bytes;

    length = (int)*plength;
    tbytes = 0;
    *plength = 0;

    if (-2 == dir)
    {
        if (sizeof debug_socket->send_oob_buffer < length)
            return vm_result(VM_ERROR_MISUSE, 0);

        AcquireSRWLockExclusive(&debug_socket->send_oob_lock);
        memcpy(debug_socket->send_oob_buffer, buffer,
            debug_socket->send_oob_length = length);
        ReleaseSRWLockExclusive(&debug_socket->send_oob_lock);

        /* signal the stop event without setting is_stopped */
        WSASetEvent(debug_server->stop_event);

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
            AcquireSRWLockExclusive(&debug_socket->send_oob_lock);
            memcpy(send_oob_buffer, debug_socket->send_oob_buffer,
                send_oob_length = debug_socket->send_oob_length);
            debug_socket->send_oob_length = 0;
            ReleaseSRWLockExclusive(&debug_socket->send_oob_lock);
            if (0 < send_oob_length)
                vm_debug_server_strm(socket0, -1, send_oob_buffer, &send_oob_length);

            bytes = recv(debug_socket->socket, buffer, length, 0);
            if (0 <= bytes)
            {
                if (debug_socket->instance->config.logf &&
                    0 != (debug_socket->instance->config.log_flags & VM_CONFIG_LOG_DEBUGSERVER))
                {
                    char buf[16];
                    wsprintfA(buf, "RECV: %%.%ds", 512 > bytes ? (int)bytes : 512);
                    debug_socket->instance->config.logf(buf, buffer);
                }
                tbytes += bytes;
                break;
            }
        }
        else
        {
            bytes = send(debug_socket->socket, buffer, length, 0);
            if (0 <= bytes)
            {
                if (debug_socket->instance->config.logf &&
                    0 != (debug_socket->instance->config.log_flags & VM_CONFIG_LOG_DEBUGSERVER))
                {
                    char buf[16];
                    wsprintfA(buf, "SEND: %%.%ds", 512 > bytes ? (int)bytes : 512);
                    debug_socket->instance->config.logf(buf, buffer);
                }
                tbytes += bytes;
                buffer = (char *)buffer + bytes;
                length -= (size_t)bytes;
                if (0 < length)
                    continue;
                else
                    break;
            }
        }

        if (WSAEWOULDBLOCK == WSAGetLastError())
        {
            if (!vm_debug_server_poll(debug_server,
                debug_socket->socket, debug_socket->event, +1 == dir ? FD_READ : FD_WRITE))
            {
                result = vm_result(VM_ERROR_TERMINATED, 0);
                goto exit;
            }
            continue;
        }

        result = vm_result(VM_ERROR_NETWORK, WSAGetLastError());
        goto exit;
    }

    *plength = tbytes;
    result = VM_RESULT_SUCCESS;

exit:
    return result;
}
