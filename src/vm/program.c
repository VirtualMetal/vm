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

void vprintlog(int fd, const char *format, va_list ap)
{
    char buf[4 + 1024 + 1];
    size_t len;

    buf[0] = 'v';
    buf[1] = 'm';
    buf[2] = ':';
    buf[3] = ' ';
    vsprintf(buf + 4, format, ap);
    len = strlen(buf);
    buf[len++] = '\n';
    buf[len] = '\0';
    write(fd, buf, len);
}

void printlog(int fd, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vprintlog(fd, format, ap);
    va_end(ap);
}

void info(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vprintlog(STDOUT_FILENO, format, ap);
    va_end(ap);
}

void warn(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vprintlog(STDERR_FILENO, format, ap);
    va_end(ap);
}

int main(int argc, char **argv)
{
    vm_result_t result;
    vm_config_t default_config;
    int reason;

    memset(&default_config, 0, sizeof default_config);
    default_config.debug_log = warn;
    default_config.vcpu_count = 1;

    result = vm_run(&default_config, argv + 1);
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
