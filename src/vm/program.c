/**
 * @file vm/program.c
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

static int vm_run(int argc, char **argv)
{
    vm_result_t result;
    vm_config_t config;
    vm_t *instance = 0;

    memset(&config, 0, sizeof config);
    config.cpu_count = 1;
    config.memory_size = 4096;

    result = vm_create(&config, &instance);
    if (!vm_result_check(result))
        goto exit;

    vm_set_debug_log(instance, (unsigned)-1);

    result = vm_start(instance);
    if (!vm_result_check(result))
        goto exit;

    vm_wait(instance);

exit:
    if (0 != instance)
        vm_delete(instance);

    return vm_result_check(result) ? 0 : 1;
}

int main(int argc, char **argv)
{
    return vm_run(argc, argv);
}

EXEMAIN;
