/**
 * @file vm-tests.c
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
#include <tlib/testsuite.h>

int main(int argc, char **argv)
{
    tlib_run_tests(argc, argv);
    return 0;
}
