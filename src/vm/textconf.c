/**
 * @file vm/textconf.c
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

#define VM_PARSE_TEXTFILE_MAX           (1024 * 1024)
#define VM_PARSE_TEXTLINE_MAX           (1024 * 1024)

static vm_result_t vm_parse_text_config_internal(int *ptconfigc, char ***ptconfigv);
static vm_result_t vm_parse_text_config_file(const char *path,
    int *pfconfigc, char ***pfconfigv, char **ptextbuf);

vm_result_t vm_parse_text_config(int *ptconfigc, char ***ptconfigv)
{
    int tconfigc = 0 != ptconfigc ? *ptconfigc : 0;
    char **tconfigv = 0 != ptconfigv ? *ptconfigv : 0;

    for (int i = 0; tconfigc > i; i++)
        for (const char *p = tconfigv[i]; *p; p++)
        {
#if defined(_WIN64)
            if ('/' == *p || '\\' == *p)
#else
            if ('/' == *p)
#endif
                return vm_parse_text_config_internal(ptconfigc, ptconfigv);
            else if ('=' == *p)
                break;
        }

    return VM_RESULT_SUCCESS;
}

static vm_result_t vm_parse_text_config_internal(int *ptconfigc, char ***ptconfigv)
{
    vm_result_t result;
    int tconfigc = *ptconfigc, fconfigc = 0;
    char **tconfigv = *ptconfigv, **fconfigv = 0, *textbuf = 0;
    void **index = 0, **newindex;
    int has_parsed_file;

    *ptconfigc = 0;
    *ptconfigv = 0;

    index = malloc((size_t)(1 + tconfigc + 1) * sizeof(void *));
    if (0 == index)
    {
        result = vm_result(VM_ERROR_MEMORY, 0);
        goto exit;
    }
    index[0] = index;
    index++;
    memcpy(index, tconfigv, (size_t)(tconfigc + 1) * sizeof(void *));

    tconfigv = (char **)index;

    for (int i = 0; tconfigc > i;)
    {
        has_parsed_file = 0;
        for (const char *p = tconfigv[i]; *p; p++)
        {
#if defined(_WIN64)
            if ('/' == *p || '\\' == *p)
#else
            if ('/' == *p)
#endif
            {
                result = vm_parse_text_config_file(tconfigv[i], &fconfigc, &fconfigv, &textbuf);
                if (!vm_result_check(result))
                    goto exit;
                has_parsed_file = 1;
                break;
            }
            else if ('=' == *p)
                break;
        }
        if (!has_parsed_file)
        {
            i++;
            continue;
        }

        if (VM_PARSE_TEXTLINE_MAX < tconfigc + fconfigc)
        {
            result = vm_result(VM_ERROR_MEMORY, 0);
            goto exit;
        }

        newindex = malloc(
            (size_t)(index - (void **)index[-1] + 1 + tconfigc + fconfigc) * sizeof(void *));
        if (0 == newindex)
        {
            result = vm_result(VM_ERROR_MEMORY, 0);
            goto exit;
        }
        newindex[index - (void **)index[-1]] = newindex;
        newindex += index - (void **)index[-1] + 1;
        memcpy(newindex[-1], index[-1], (size_t)(index - (void **)index[-1] - 1) * sizeof(void *));
        newindex[-2] = textbuf;
        memcpy(newindex, index, (size_t)i * sizeof(void *));
        memcpy(newindex + i, fconfigv, (size_t)fconfigc * sizeof(void *));
        memcpy(newindex + i + fconfigc, index + i + 1, (size_t)(tconfigc - i) * sizeof(void *));

        free(index[-1]);
        free(fconfigv);
        index = newindex;
        newindex = 0;
        fconfigv = 0;
        textbuf = 0;

        tconfigc += fconfigc - 1;
        tconfigv = (char **)index;
    }

    *ptconfigc = tconfigc;
    *ptconfigv = tconfigv;
    index = 0;
    result = VM_RESULT_SUCCESS;

exit:
    if (0 != index)
        vm_free_text_config((char **)index);

    free(fconfigv);
    free(textbuf);

    return result;
}

static vm_result_t vm_parse_text_config_file(const char *path,
    int *pfconfigc, char ***pfconfigv, char **ptextbuf)
{
    vm_result_t result;
    int fconfigc;
    char **fconfigv = 0, *textbuf = 0;
    int file = -1;
    struct stat stbuf;
    ssize_t bytes;

    *pfconfigc = 0;
    *pfconfigv = 0;
    *ptextbuf = 0;

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

    if (0 == stbuf.st_size)
    {
        result = VM_RESULT_SUCCESS;
        goto exit;
    }

    if (VM_PARSE_TEXTFILE_MAX < stbuf.st_size)
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
    textbuf[bytes] = '\0';

    fconfigc = 0;
    for (char *p = textbuf, *endp = p + bytes; endp > p; p++)
    {
        switch (*p)
        {
        case '\r': case '\n':
            *p = '\0';
            break;
        }
        if ((textbuf == p || '\0' == p[-1]) && '\0' != p[0])
            fconfigc++;
    }

    if (0 == fconfigc)
    {
        result = VM_RESULT_SUCCESS;
        goto exit;
    }

    fconfigv = malloc((size_t)(fconfigc + 1) * sizeof(char *));
    if (0 == fconfigv)
    {
        result = vm_result(VM_ERROR_MEMORY, 0);
        goto exit;
    }

    fconfigc = 0;
    for (char *p = textbuf, *endp = p + bytes; endp > p; p++)
        if ((textbuf == p || '\0' == p[-1]) && '\0' != p[0])
            fconfigv[fconfigc++] = p;
    fconfigv[fconfigc] = 0;

    *pfconfigc = fconfigc;
    *pfconfigv = fconfigv;
    *ptextbuf = textbuf;
    fconfigv = 0;
    textbuf = 0;
    result = VM_RESULT_SUCCESS;

exit:
    free(fconfigv);
    free(textbuf);

    if (-1 != file)
        close(file);

    return result;
}

vm_result_t vm_free_text_config(char **tconfigv)
{
    void **index = (void **)tconfigv;

    for (void **pp = index[-1]; index - 1 != pp; pp++)
        free(*pp);

    free(index[-1]);

    return VM_RESULT_SUCCESS;
}
