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

vm_result_t vm_run(const vm_config_t *default_config, char **text_config)
{
    /* command/command-with-index macros */
#define CMD(S)  (0 == invariant_strncmp(p, S "=", sizeof S) && \
    (bmap_set(valid, (unsigned)(pp - text_config), 1), p += sizeof S))
#define CMI(S,L,U)\
    (0 == invariant_strncmp(p, S, sizeof S - 1) && \
    (cmi = (unsigned)strtoullint(p + sizeof S - 1, &cmip, +10), '=' == *cmip) && \
    (L) <= cmi && cmi <= (U) && \
    (bmap_set(valid, (unsigned)(pp - text_config), 1), p = cmip + 1))
    /* check macro */
#define CHK(C)  if (C) ; else { result = vm_result(VM_ERROR_MISUSE, pp - text_config + 1); goto exit; }
    /* page offset/length macros -- work for AMD64; also for ARM64 with a 4KB granule */
#define PGO(P,L)(((P) & (0x0000ff8000000000ULL >> (((L) - 1) * 9))) >> (48 - (L) * 9) << 3)
#define PGL(L)  ((0x8000000000ULL >> (((L) - 1) * 9)))

    vm_result_t result;
    vm_config_t config;
    unsigned config_count, invalid_index;
    bmap_t valid[bmap_declcount(4096)] = { 0 };
    vm_t *instance = 0;
    vm_count_t guest_address, length, count, page_address;
    vm_mmap_t *map;
    int file;
    char *cmip; unsigned cmi;

    config = *default_config;
    config.debug_log = 0;

    config_count = 0;
    for (char **pp = text_config, *p = *pp; p; p = *++pp)
    {
        config_count++;
        if ('#' == *p || '\0' == *p)
            bmap_set(valid, (unsigned)(pp - text_config), 1);
    }
    if (bmap_capacity(valid) < config_count)
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    for (char **pp = text_config, *p = *pp; p; p = *++pp)
    {
        if (CMD("debug_log"))
        {
            config.debug_log = strtoullint(p, &p, +1) ? default_config->debug_log : 0;
            CHK('\0' == *p);
        }
        else
        if (CMD("vcpu_count"))
        {
            config.vcpu_count = strtoullint(p, &p, +1);
            CHK('\0' == *p);
        }
        else
        if (CMD("vcpu_entry"))
        {
            config.vcpu_entry = strtoullint(p, &p, +1);
            CHK('\0' == *p);
        }
        else
        if (CMD("vcpu_table"))
        {
            config.vcpu_table = strtoullint(p, &p, +1);
            CHK('\0' == *p);
        }
        else
        if (CMD("page_table") || CMD("pg0"))
        {
            config.page_table = strtoullint(p, &p, +1);
            CHK('\0' == *p);
        }
    }

    result = vm_create(&config, &instance);
    if (!vm_result_check(result))
        goto exit;

    for (char **pp = text_config, *p = *pp; p; p = *++pp)
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
                    result = vm_result(VM_ERROR_FILE, 0);
                    goto exit;
                }
            }

            result = vm_mmap(instance, 0, file, guest_address, length, &map);
                /* do not track map; vm_delete will free it */

            if (',' == *p)
                close(file);

            if (!vm_result_check(result))
                goto exit;
        }
    }

    for (char **pp = text_config, *p = *pp; p; p = *++pp)
    {
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
    }

    if ((invalid_index = bmap_find(valid, bmap_capacity(valid), 0)) < config_count)
    {
        result = vm_result(VM_ERROR_MISUSE, invalid_index + 1);
        goto exit;
    }

    result = vm_start(instance);
    if (!vm_result_check(result))
        goto exit;

    result = vm_wait(instance);

exit:
    if (0 != instance)
        vm_delete(instance);

    return result;

#undef CMD
#undef CMI
#undef CHK
#undef PGO
#undef PGL
}
