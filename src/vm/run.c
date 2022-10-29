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

#include <vm/vm.h>
#include <vm/internal.h>

vm_result_t vm_run(char **text_config)
{
    /* text parsing macros */
#define CMD(S)  (0 == invariant_strncmp(p, S "=", sizeof S) ? (p += sizeof S) : 0)
#define CHK(C)  if (C) ; else { result = vm_result(VM_ERROR_MISUSE, (pp - text_config) + 1); goto exit; }
    /* page offset macro -- works for AMD64; also for ARM64 with a 4KB granule */
#define PGO(P,L)(((P) & (0x0000ff8000000000ULL >> (((L) - 1) * 9))) >> (48 - (L) * 9) << 3)

    vm_result_t result;
    vm_config_t config;
    vm_t *instance = 0;
    vm_count_t guest_address, length, page_address;
    vm_mmap_t *map;
    int file, page_level;

    memset(&config, 0, sizeof config);
    config.vcpu_count = 1;

    for (char **pp = text_config, *p = *pp++; p; p = *pp++)
    {
        if (CMD("debug"))
        {
            config.debug_flags = strtoullint(p, &p, -1);
            CHK('\0' == *p);
        }
        else
        if (CMD("vcpu"))
        {
            config.vcpu_count = strtoullint(p, &p, +1);
            CHK('\0' == *p);
        }
        else
        if (CMD("entry"))
        {
            config.vcpu_entry = strtoullint(p, &p, +1);
            CHK('\0' == *p);
        }
        else
        if (CMD("pg0"))
        {
            config.page_table = strtoullint(p, &p, +1);
            CHK('\0' == *p);
        }
    }

    result = vm_create(&config, &instance);
    if (!vm_result_check(result))
        goto exit;

    for (char **pp = text_config, *p = *pp++; p; p = *pp++)
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

    for (char **pp = text_config, *p = *pp++; p; p = *pp++)
    {
        if (CMD("pg1") || CMD("pg2") || CMD("pg3") || CMD("pg4"))
        {
            page_level = p[-2] - '0';
            guest_address = strtoullint(p, &p, +1);
            CHK('\0' == *p);

            page_address = config.page_table;
            for (int level = 1; page_level >= level; level++)
            {
                if (page_level > level)
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
                    length = sizeof guest_address;
                    vm_mwrite(instance,
                        &guest_address,
                        page_address + PGO(guest_address, level),
                        &length);
                    CHK(sizeof guest_address == length);
                }
            }
        }
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
#undef CHK
#undef PGO
}
