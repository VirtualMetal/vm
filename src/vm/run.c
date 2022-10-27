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
#define CONFIGVAL(p, S)                 (0 == invariant_strncmp(p, S "=", sizeof S) ? ((p) += sizeof S) : 0)

    vm_result_t result;
    vm_config_t config;
    vm_t *instance = 0;
    vm_count_t guest_address, length;
    vm_mmap_t *map;
    int file;

    memset(&config, 0, sizeof config);
    config.vcpu_count = 1;

    for (char **pp = text_config, *p = *pp++; p; p = *pp++)
    {
        if (CONFIGVAL(p, "debug"))
            config.debug_flags = strtoullint(p, 0, 0, 1);
        else
        if (CONFIGVAL(p, "vcpu"))
            config.vcpu_count = strtoullint(p, 0, 0, 1);
        else
        if (CONFIGVAL(p, "entry"))
            config.vcpu_entry = strtoullint(p, 0, 0, 1);
    }

    result = vm_create(&config, &instance);
    if (!vm_result_check(result))
        goto exit;

    for (char **pp = text_config, *p = *pp++; p; p = *pp++)
    {
        if (CONFIGVAL(p, "mmap"))
        {
            guest_address = strtoullint(p, &p, 0, 1);
            if (',' != *p)
                continue;
            length = strtoullint(p + 1, &p, 0, 1);
            if (',' != *p && '\0' != *p)
                continue;

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

    result = vm_start(instance);
    if (!vm_result_check(result))
        goto exit;

    result = vm_wait(instance);

exit:
    if (0 != instance)
        vm_delete(instance);

    return result;

#undef CONFIGVAL
}
