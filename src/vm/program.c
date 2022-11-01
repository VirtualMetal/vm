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

#include <vm/internal.h>

#define PROGNAME                        "vm"
#define info(format, ...)               (printfd(STDOUT_FILENO, PROGNAME ": " format "\n", __VA_ARGS__))
#define warn(format, ...)               (printfd(STDERR_FILENO, PROGNAME ": " format "\n", __VA_ARGS__))

void vprintfd(int fd, const char *format, va_list ap)
{
    char buf[1024];

    vsprintf(buf, format, ap);
    buf[sizeof buf - 1] = '\0';
    write(fd, buf, strlen(buf));
}

void printfd(int fd, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vprintfd(fd, format, ap);
    va_end(ap);
}

int main(int argc, char **argv)
{
    vm_result_t result;
    int reason;

    result = vm_run(argv + 1);
    if (vm_result_check(result))
        return 0;
    else if (VM_ERROR_MISUSE != vm_result_error(result))
        return 1;
    else
    {
        reason = (int)vm_result_reason(result);
        if (1 <= reason && reason < argc)
            warn("config error: %s", argv[reason]);
        return 2;
    }
}

EXEMAIN;
