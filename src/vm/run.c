/**
 * @file vm/run.c
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

static vm_result_t vm_runcmd_dispatch(void *context, vm_runcmd_t *runcmds,
    char phase, bmap_t *valid, unsigned index, char *p);

VM_API
vm_result_t vm_run(const vm_config_t *default_config, char **tconfigv, vm_t **pinstance)
{
    return vm_run_ex(default_config, tconfigv, 0, pinstance);
}

VM_API
vm_result_t vm_run_ex(const vm_config_t *default_config, char **tconfigv, vm_runcmd_t *runcmds,
    vm_t **pinstance)
{
    /* command/command-with-index macros */
#define CMD(S)\
    (0 == invariant_strncmp(p, S, sizeof S - 1) && \
    (('=' == p[sizeof S - 1] && (bmap_set(valid, (unsigned)(pp - tconfigv), 1), p += sizeof S)) || \
    ('\0' == p[sizeof S - 1] && (bmap_set(valid, (unsigned)(pp - tconfigv), 1), p = "1"))))
#define CMI(S,L,U)\
    (0 == invariant_strncmp(p, S, sizeof S - 1) && \
    (cmi = (unsigned)strtoullint(p + sizeof S - 1, &cmip, +10), '=' == *cmip) && \
    (L) <= cmi && cmi <= (U) && \
    (bmap_set(valid, (unsigned)(pp - tconfigv), 1), p = cmip + 1))
    /* check macro */
#define CHK(C)  do \
    if (C) ; else { result = vm_result(VM_ERROR_CONFIG, pp - tconfigv + 1); goto exit; } \
    while (0)
    /* page offset/length macros -- work for AMD64; also for ARM64 with a 4KB granule */
#define PGO(P,L)(((P) & (0x0000ff8000000000ULL >> (((L) - 1) * 9))) >> (48 - (L) * 9) << 3)
#define PGL(L)  ((0x8000000000ULL >> (((L) - 1) * 9)))

    vm_result_t result;
    vm_config_t config;
    int tconfigc;
    unsigned invalid_index;
    bmap_t valid[bmap_declcount(4096)];
    vm_t *instance = 0;
    vm_count_t guest_address, length, count, stride, page_address;
    vm_mmap_t *map;
    char debug_hostbuf[256], *debug_host = 0, *debug_port = 0;
    vm_count_t debug_break = 0;
    int file;
    char mbuf[1024];
    char *cmip; unsigned cmi;

    *pinstance = 0;

    config = *default_config;

    memset(valid, 0, sizeof valid);

    tconfigc = 0;
    for (char **pp = tconfigv, *p = *pp; p; p = *++pp)
    {
        tconfigc++;
        if (bmap_capacity(valid) < tconfigc)
        {
            result = vm_result(VM_ERROR_CONFIG, 0);
            goto exit;
        }
        if ('#' == *p || '\0' == *p)
            bmap_set(valid, (unsigned)(pp - tconfigv), 1);
    }

    /*
     * Create configuration
     */
    for (char **pp = tconfigv, *p = *pp; p; p = *++pp)
    {
        if (CMD("plugin"))
        {
            CHK(0 == runcmds);

            void *plugin = dlopen(p, RTLD_NOW | RTLD_LOCAL);
#if defined(__linux__)
            /* Linux: if path does not end in .so, add and retry (match Windows .dll behavior) */
            if (0 == plugin &&
                (3 > (length = strlen(p)) || 0 != invariant_strcmp(p + length - 3, ".so")) &&
                PATH_MAX > length)
            {
                char path[PATH_MAX];
                memcpy(path, p, length);
                memcpy(path + length, ".so", 3 + 1);
                plugin = dlopen(path, RTLD_NOW | RTLD_LOCAL);
            }
#endif
            CHK(0 != plugin);

            vm_plugin_runcmds_t *vm_plugin_runcmds = dlsym(plugin, "vm_plugin_runcmds");
            if (0 == vm_plugin_runcmds)
                dlclose(plugin);
            CHK(0 != vm_plugin_runcmds);

            runcmds = vm_plugin_runcmds();
        }
        else if (CMD("log"))
        {
            config.logf = strtoullint(p, &p, +1) ? config.logf : 0;
            CHK('\0' == *p);
        }
        else
        if (CMD("log_flags"))
        {
            config.log_flags = strtoullint(p, &p, +1);
            CHK('\0' == *p);
        }
        else
        if (CMD("compat_flags"))
        {
            config.compat_flags = strtoullint(p, &p, +1);
            CHK('\0' == *p);
        }
        else
        if (CMD("vcpu_count"))
        {
            config.vcpu_count = strtoullint(p, &p, +1);
            CHK('\0' == *p);
            CHK(VM_CONFIG_VCPU_COUNT_MAX >= config.vcpu_count);
        }
        else
        if (CMD("passthrough"))
        {
            config.passthrough = !!strtoullint(p, &p, +1);
            CHK('\0' == *p);
        }
        else
        if (CMD("vpic"))
        {
            config.vpic = !!strtoullint(p, &p, +1);
            CHK('\0' == *p);
        }
        else
        {
            result = vm_runcmd_dispatch(&config, runcmds,
                VM_RUNCMD_PHASE_CREATE, valid, (unsigned)(pp - tconfigv), p);
            if (!vm_result_check(result))
                goto exit;
        }
    }

    result = vm_create(&config, &instance);
    if (!vm_result_check(result))
        goto exit;

    /*
     * Memory configuration
     */
    for (char **pp = tconfigv, *p = *pp; p; p = *++pp)
    {
        if (CMD("mmap"))
        {
            guest_address = strtoullint(p, &p, +1);
            CHK(',' == *p);
            length = strtoullint(p + 1, &p, +1);
            CHK(',' == *p || '\0' == *p);

            file = -1;
            if (',' == *p)
            {
                file = open(p + 1, O_RDONLY);
                if (-1 == file)
                {
                    result = vm_result(VM_ERROR_FILE, errno);
                    goto exit;
                }
            }

            result = vm_mmap(instance, guest_address, length, 0, file, 0, 0, &map);
                /* do not track map; vm_delete will free it */

            if (',' == *p)
                close(file);

            if (!vm_result_check(result))
                goto exit;
        }
        else
        if (CMD("load") || CMD("exec"))
        {
            guest_address = strtoullint(p, &p, +1);
            CHK(',' == *p);
            length = strtoullint(p + 1, &p, +1);
            CHK(',' == *p);

            file = open(p + 1, O_RDONLY);
            if (-1 == file)
            {
                result = vm_result(VM_ERROR_FILE, errno);
                goto exit;
            }

            result = vm_load(instance, guest_address, length, file,
                'e' == (*pp)[0] ? VM_LOAD_EXEC | VM_LOAD_EXEC_REPORT : 0);

            close(file);

            if (!vm_result_check(result))
                goto exit;
        }
        else
        {
            result = vm_runcmd_dispatch(instance, runcmds,
                VM_RUNCMD_PHASE_MEMORY, valid, (unsigned)(pp - tconfigv), p);
            if (!vm_result_check(result))
                goto exit;
        }
    }

    /*
     * Start configuration
     */
    for (char **pp = tconfigv, *p = *pp; p; p = *++pp)
    {
        if (CMD("vcpu_entry"))
        {
            config.vcpu_entry = strtoullint(p, &p, +1);
            CHK('\0' == *p);
            vm_setconfig(instance, &config, VM_CONFIG_BIT(vcpu_entry));
        }
        else
        if (CMD("vcpu_args"))
        {
            for (unsigned i = 0; sizeof config.vcpu_args / sizeof config.vcpu_args[0] > i; i++)
            {
                config.vcpu_args[i] = strtoullint(p, &p, +1);
                CHK(',' == *p || '\0' == *p);
                vm_setconfig(instance, &config, VM_CONFIG_BIT(vcpu_args[i]));
                if ('\0' == *p)
                    break;
                p++;
            }
            CHK('\0' == *p);
        }
        else
        if (CMD("vcpu_table"))
        {
            config.vcpu_table = strtoullint(p, &p, +1);
            CHK(',' == *p || '\0' == *p);
            if (',' == *p)
            {
                stride = strtoullint(p + 1, &p, +1);
                CHK('\0' == *p);
            }
            else
                stride = 0;
            config.vcpu_table &= ~0xff;
            config.vcpu_table |= stride & 0xff;
            vm_setconfig(instance, &config, VM_CONFIG_BIT(vcpu_table));
        }
        else
        if (CMD("vcpu_alt_table") || CMD("idt"))
        {
            config.vcpu_alt_table = strtoullint(p, &p, +1);
            CHK('\0' == *p);
            vm_setconfig(instance, &config, VM_CONFIG_BIT(vcpu_alt_table));
        }
#if (defined(_MSC_VER) && defined(_M_X64)) || (defined(__GNUC__) && defined(__x86_64__))
        else
        if (CMD("idt_intg") || CMD("idt_sysg"))
        {
            struct arch_x64_gate_desc gate;
            count = strtoullint(p, &p, +1);
            CHK(',' == *p);
            CHK(0 <= count && count <= 255);
            guest_address = strtoullint(p + 1, &p, +1);
            CHK('\0' == *p);
            if ('i' == (*pp)[4])
                arch_x64_intg_init(&gate, guest_address, 1);
            else
                arch_x64_sysg_init(&gate, guest_address, 1);
            page_address = config.vcpu_alt_table;
            length = sizeof gate;
            vm_mwrite(instance,
                &gate,
                page_address + count * sizeof gate,
                &length);
            CHK(sizeof gate == length);
        }
#endif
        else
        if (CMD("vcpu_mailbox"))
        {
            config.vcpu_mailbox = strtoullint(p, &p, +1);
            CHK('\0' == *p);
            vm_setconfig(instance, &config, VM_CONFIG_BIT(vcpu_mailbox));
        }
        else
        if (CMD("page_table") || CMD("pg0"))
        {
            config.page_table = strtoullint(p, &p, +1);
            CHK('\0' == *p);
            vm_setconfig(instance, &config, VM_CONFIG_BIT(page_table));
        }
        else
        if (CMI("pg", 1, 4))
        {
            guest_address = strtoullint(p, &p, +1);
            CHK(',' == *p || '\0' == *p);
            if (',' == *p)
            {
                count = strtoullint(p + 1, &p, +1);
                CHK('\0' == *p);
            }
            else
                count = 1;
            page_address = config.page_table;
            for (unsigned level = 1; cmi >= level; level++)
            {
                if (cmi > level)
                {
                    length = sizeof page_address;
                    vm_mread(instance,
                        page_address + PGO(guest_address, level),
                        &page_address,
                        &length);
                    CHK(sizeof page_address == length);
                    page_address &= 0x000ffffffffff000ULL;
                }
                else
                {
                    for (; 0 < count; count--)
                    {
                        length = sizeof guest_address;
                        vm_mwrite(instance,
                            &guest_address,
                            page_address + PGO(guest_address, level),
                            &length);
                        CHK(sizeof guest_address == length);
                        guest_address += PGL(level);
                    }
                }
            }
        }
        else
        if (CMD("data"))
        {
            guest_address = strtoullint(p, &p, +1);
            CHK(',' == *p);
            count = strtoullint(p + 1, &p, +1);
            CHK(',' == *p || '\0' == *p);
            CHK(0 < count && count <= sizeof mbuf);
            memset(mbuf, 0, count);
            for (char *q = mbuf, *endq = q + count; *p && *++p && endq > q; q++)
            {
                *q = (char)strtoullint(p, &p, +1);
                CHK(',' == *p || '\0' == *p);
            }
            length = count;
            vm_mwrite(instance,
                mbuf,
                guest_address,
                &length);
            CHK(count == length);
        }
        else
        if (CMD("debug_host"))
        {
            int brk = '[' == *p ? (p++, ']') : ':';
            for (char *q = debug_hostbuf, *endq = q + sizeof debug_hostbuf; endq > q && (*q = *p); p++, q++)
                if (brk == *q)
                {
                    *q = '\0';
                    break;
                }
            if (']' == brk)
                CHK(']' == *p++);
            CHK(':' == *p++);
            debug_hostbuf[sizeof debug_hostbuf - 1] = '\0';
            debug_host = *debug_hostbuf ? debug_hostbuf : 0;
            debug_port = p;
        }
        else
        if (CMD("debug_break"))
        {
            debug_break = strtoullint(p, &p, +1);
            CHK('\0' == *p);
        }
        else
        {
            result = vm_runcmd_dispatch(instance, runcmds,
                VM_RUNCMD_PHASE_START, valid, (unsigned)(pp - tconfigv), p);
            if (!vm_result_check(result))
                goto exit;
        }
    }

    invalid_index = bmap_find(valid, bmap_capacity(valid), 0);
    if (invalid_index < (unsigned)tconfigc)
    {
        result = vm_result(VM_ERROR_CONFIG, invalid_index + 1);
        goto exit;
    }

    if (debug_break)
    {
        result = vm_debug(instance, VM_DEBUG_ATTACH, 0, 0, 0, 0);
        if (!vm_result_check(result))
            goto exit;
        result = vm_debug(instance, VM_DEBUG_BREAK, 0, 0, 0, 0);
        if (!vm_result_check(result))
            goto exit;
    }

    result = vm_start(instance);
    if (!vm_result_check(result))
        goto exit;

    if (debug_break)
    {
        result = vm_debug(instance, VM_DEBUG_WAIT, 0, 0, 0, 0);
        if (!vm_result_check(result))
            goto exit;
    }

    if (0 != debug_port)
    {
        result = vm_debug_server_start(instance, debug_host, debug_port);
        if (!vm_result_check(result))
            goto exit;
    }

    *pinstance = instance;
    result = VM_RESULT_SUCCESS;

exit:
    if (!vm_result_check(result) && 0 != instance)
        vm_delete(instance);

    return result;

#undef CMD
#undef CMI
#undef CHK
#undef PGO
#undef PGL
}

static vm_result_t vm_runcmd_dispatch(void *context, vm_runcmd_t *runcmds,
    char phase, bmap_t *valid, unsigned index, char *p)
{
    vm_result_t result = VM_RESULT_SUCCESS;
    for (vm_runcmd_t *runcmd = runcmds; runcmd && runcmd->name; runcmd++)
        if (VM_RUNCMD_PHASE_ALL == runcmd->name[0] || phase == runcmd->name[0])
        {
            size_t len = strlen(runcmd->name + 1);
            if ((0 == invariant_strncmp(p, runcmd->name + 1, len)) &&
                (('=' == p[len] && (bmap_set(valid, index, 1), p += len + 1)) ||
                ('\0' == p[len] && (bmap_set(valid, index, 1), p = "1"))))
            {
                result = runcmd->fn(context, runcmd, phase, p);
                if (VM_ERROR_CONFIG == vm_result_error(result))
                    result = vm_result(VM_ERROR_CONFIG, index + 1);
                break;
            }
        }
    return result;
}
