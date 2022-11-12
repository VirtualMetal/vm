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

static vm_result_t parse_text_config(const char *path, char ***ptext_config, unsigned *pconfig_count)
{
    vm_result_t result;
    int file = -1;
    struct stat stbuf;
    ssize_t bytes;
    char **text_config = 0, *textbuf = 0, *text;
    unsigned config_count;

    *ptext_config = 0;
    *pconfig_count = 0;

    file = open(path, O_RDONLY);
    if (-1 == file)
    {
        result = vm_result(VM_ERROR_FILE, errno);
        goto exit;
    }

    if (-1 == fstat(file, &stbuf))
    {
        result = vm_result(VM_ERROR_FILE, errno);
        goto exit;
    }

    if (64 * 1024 < stbuf.st_size)
    {
        result = vm_result(VM_ERROR_MEMORY, 0);
        goto exit;
    }

    textbuf = malloc((size_t)stbuf.st_size + 1);
    if (0 == textbuf)
    {
        result = vm_result(VM_ERROR_MEMORY, 0);
        goto exit;
    }

    bytes = pread(file, textbuf, (size_t)stbuf.st_size, 0);
    if (-1 == bytes)
    {
        result = vm_result(VM_ERROR_FILE, errno);
        goto exit;
    }
    textbuf[bytes++] = '\0';

    text = textbuf;
    config_count = 0;
    for (char *p = text, *endp = p + bytes; endp > p; p++)
    {
        switch (*p)
        {
        case '\r': case '\n':
            *p = '\0';
            break;
        }
        if (text == p || ('\0' == p[-1] && '\0' != p[0]))
            config_count++;
    }
    config_count++;

    text_config = malloc(config_count * sizeof(void *) + (size_t)bytes);
    if (0 == text_config)
    {
        result = vm_result(VM_ERROR_MEMORY, 0);
        goto exit;
    }

    memcpy(text_config + config_count, text, (size_t)bytes);

    text = (char *)(text_config + config_count);
    config_count = 0;
    for (char *p = text, *endp = p + bytes; endp > p; p++)
        if (text == p || ('\0' == p[-1] && '\0' != p[0]))
            text_config[config_count++] = p;
    text_config[config_count] = 0;

    *ptext_config = text_config;
    *pconfig_count = config_count;
    result = VM_RESULT_SUCCESS;

exit:
    free(textbuf);

    if (-1 != file)
        close(file);

    if (!vm_result_check(result) && 0 != text_config)
        free(text_config);

    return result;
}

int main(int argc, char **argv)
{
    vm_result_t result;
    vm_result_t reason;
    char **text_config;
    unsigned config_count;
    vm_config_t default_config;

    text_config = argv + 1;
    config_count = (unsigned)(argc - 1);
    if (2 <= argc)
    {
        for (const char *p = argv[1]; *p; p++)
        {
#if defined(_WIN64)
            if ('/' == *p || '\\' == *p)
#else
            if ('/' == *p)
#endif
            {
                result = parse_text_config(argv[1], &text_config, &config_count);
                if (!vm_result_check(result))
                    goto exit;
                break;
            }
            else if ('=' == *p)
                break;
        }
    }

    memset(&default_config, 0, sizeof default_config);
    default_config.debug_log = warn;
    default_config.vcpu_count = 1;

    result = vm_run(&default_config, text_config);

exit:
    /* do not free text_config: it is needed below and will be freed by system */

    if (vm_result_check(result))
        return 0;
    else if (VM_ERROR_CONFIG == vm_result_error(result))
    {
        reason = vm_result_reason(result);
        if (1 <= reason && reason <= config_count)
            warn("config error: %s", text_config[reason - 1]);
        else
            warn("config error");
        return 2;
    }
    else
    {
        warn("error: %d(%x)",
            (int)(vm_result_error(result) >> 48),
            (unsigned)vm_result_reason(result));
        return 1;
    }
}

EXEMAIN;
