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

int main(int argc, char **argv)
{
    vm_result_t result;

    result = vm_run(argv + 1);

    return vm_result_check(result) ? 0 : 1;
}

EXEMAIN;
