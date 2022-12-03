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
    vm_result_t reason;
    vm_config_t default_config;
    int argi, tconfigc;
    char **tconfigv;
    vm_t *instance = 0;

    memset(&default_config, 0, sizeof default_config);
    default_config.logf = warn;
    default_config.vcpu_count = 1;

    for (argi = 1; argc > argi; argi++)
    {
        const char *a = argv[argi];
        if ('-' != a[0])
            break;
        else
        if (0 == invariant_strcmp("--", a))
        {
            argi++;
            break;
        }
        else
        if (0 == invariant_strcmp("-C", a) && argc > argi + 1)
        {
            argi++;
            if (-1 == chdir(argv[argi]))
            {
                result = vm_result(VM_ERROR_FILE, errno);
                goto exit;
            }
        }
        else
        {
            result = vm_result(VM_ERROR_CONFIG, 0);
            goto exit;
        }
    }

    tconfigc = argc - argi;
    tconfigv = argv + argi;
    if (0 == tconfigc)
    {
        result = vm_result(VM_ERROR_CONFIG, 0);
        goto exit;
    }

    result = vm_parse_text_config(&tconfigc, &tconfigv);
    if (!vm_result_check(result))
        goto exit;

    result = vm_run(&default_config, tconfigv, &instance);
    if (!vm_result_check(result))
        goto exit;

    if (tconfigv != argv + 1)
        vm_free_text_config(tconfigv);
    tconfigc = 0;
    tconfigv = 0;

    result = vm_wait(instance);

exit:
    /* some resources may not be freed (tconfigv, instance); they will be freed by the system */

    if (vm_result_check(result))
        return 0;
    else if (VM_ERROR_CONFIG == vm_result_error(result))
    {
        warn("syntax: [-C <work-dir>] [<name>=<value> | <conf-file>]...");
        reason = vm_result_reason(result);
        if (1 <= reason && reason <= (unsigned)tconfigc)
            warn("config error: %s", tconfigv[reason - 1]);
        else
            warn("config error");
        return 2;
    }
    else
    {
        warn("error: %s(%x)",
            vm_result_error_string(result),
            (unsigned)vm_result_reason(result));
        return 1;
    }
}

EXEMAIN;
