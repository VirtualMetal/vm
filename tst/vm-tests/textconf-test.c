/**
 * @file textconf-test.c
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

#include "vm-tests.h"

static void vm_parse_text_config_test(void)
{
    vm_result_t result;
    int tconfigc;
    char **tconfigv;
    char *fake_argv[] = { "n1=v1", "n2=v2", "n3=v3", "n4=v4", 0 };
    char *fileA = "./vm-tests-fileA";
    char *fileB = "./vm-tests-fileB";
    char *fileC = "./vm-tests-fileC";
    char *dataA = "\n\n#foo\n\n./vm-tests-fileB\nA1=v1\n./vm-tests-fileB\nA2=v2\n./vm-tests-fileC";
    char *dataB = "\n./vm-tests-fileC\nB1=v1\n./vm-tests-fileC\n";
    char *dataC = "\n";
    char *file_argv[] = { "n1=v1", fileA, fileB, "n2=v2", 0 };
    char *expf_argv[] = { "n1=v1", "#foo", "B1=v1", "A1=v1", "B1=v1", "A2=v2", "B1=v1", "n2=v2", 0 };
    int file;
    ssize_t bytes;

    result = vm_parse_text_config(0, 0);
    ASSERT(vm_result_check(result));

    tconfigc = 0;
    tconfigv = 0;
    result = vm_parse_text_config(&tconfigc, &tconfigv);
    ASSERT(vm_result_check(result));
    ASSERT(0 == tconfigc);
    ASSERT(0 == tconfigv);

    tconfigc = sizeof fake_argv / sizeof fake_argv[0] - 1;
    tconfigv = fake_argv;
    result = vm_parse_text_config(&tconfigc, &tconfigv);
    ASSERT(vm_result_check(result));
    ASSERT(sizeof fake_argv / sizeof fake_argv[0] - 1 == tconfigc);
    ASSERT(fake_argv == tconfigv);

    file = open(fileA, O_RDWR | O_CREAT | O_EXCL, 0666);
    ASSERT(-1 != file);
    bytes = pwrite(file, dataA, strlen(dataA), 0);
    ASSERT(strlen(dataA) == bytes);
    close(file);
    file = open(fileB, O_RDWR | O_CREAT | O_EXCL, 0666);
    ASSERT(-1 != file);
    bytes = pwrite(file, dataB, strlen(dataB), 0);
    ASSERT(strlen(dataB) == bytes);
    close(file);
    file = open(fileC, O_RDWR | O_CREAT | O_EXCL, 0666);
    ASSERT(-1 != file);
    bytes = pwrite(file, dataC, strlen(dataC), 0);
    ASSERT(strlen(dataC) == bytes);
    close(file);

    tconfigc = sizeof file_argv / sizeof file_argv[0] - 1;
    tconfigv = file_argv;
    result = vm_parse_text_config(&tconfigc, &tconfigv);
    ASSERT(vm_result_check(result));
    ASSERT(sizeof expf_argv / sizeof expf_argv[0] - 1 == tconfigc);
    for (size_t i = 0; tconfigc > i; i++)
        ASSERT(0 == strcmp(expf_argv[i], tconfigv[i]));
    ASSERT(0 == tconfigv[tconfigc]);
    result = vm_free_text_config(tconfigv);
    ASSERT(vm_result_check(result));

    unlink(fileA);
    unlink(fileB);
    unlink(fileC);
}

void textconf_tests(void)
{
    TEST(vm_parse_text_config_test);
}
