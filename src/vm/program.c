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
    if (vm_result_check(result))
        return 0;
    else if (VM_ERROR_MISUSE != vm_result_error(result))
        return 1;
    else
        // warn("bad argument #%u", (unsigned)vm_result_reason(result));
        return 2;
}

EXEMAIN;
