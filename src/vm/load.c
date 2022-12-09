/**
 * @file vm/load.c
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

#define VM_LOAD_HEADER_MAXLEN           4096

/*
 * Elf64 file format
 * See: Executable and Linking Format (ELF) Specification Version 1.2
 * See: man 5 elf
 */

typedef unsigned long long Elf64_Addr;
typedef unsigned long long Elf64_Off;
typedef unsigned short Elf64_Section;
typedef unsigned short Elf64_Versym;
typedef unsigned char Elf_Byte;
typedef unsigned short Elf64_Half;
typedef int Elf64_Sword;
typedef unsigned int Elf64_Word;
typedef long long Elf64_Sxword;
typedef unsigned long long Elf64_Xword;

#define EI_NIDENT                       16
#define EI_MAG0                         0
#define EI_MAG1                         1
#define EI_MAG2                         2
#define EI_MAG3                         3
#define EI_CLASS                        4
#define EI_DATA                         5
#define EI_VERSION                      6
#define EI_OSABI                        7
#define EI_ABIVERSION                   8

#define ELFCLASSNONE                    0
#define ELFCLASS32                      1
#define ELFCLASS64                      2

#define ELFDATANONE                     0
#define ELFDATA2LSB                     1
#define ELFDATA2MSB                     2

#define EV_NONE                         0
#define EV_CURRENT                      1

#define ET_NONE                         0
#define ET_REL                          1
#define ET_EXEC                         2
#define ET_DYN                          3
#define ET_CORE                         4

#define EM_NONE                         0
#define EM_X86_64                       62
#define EM_AARCH64                      183

#define PT_NULL                         0
#define PT_LOAD                         1
#define PT_DYNAMIC                      2
#define PT_INTERP                       3
#define PT_NOTE                         4
#define PT_SHLIB                        5
#define PT_PHDR                         6

#define PF_X                            1
#define PF_W                            2
#define PF_R                            4

typedef struct
{
    Elf_Byte e_ident[EI_NIDENT];
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;
    Elf64_Off e_phoff;
    Elf64_Off e_shoff;
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct
{
    Elf64_Word p_type;
    Elf64_Word p_flags;
    Elf64_Off p_offset;
    Elf64_Addr p_vaddr;
    Elf64_Addr p_paddr;
    Elf64_Xword p_filesz;
    Elf64_Xword p_memsz;
    Elf64_Xword p_align;
} Elf64_Phdr;

vm_result_t vm_load_elf(vm_t *instance,
    vm_count_t guest_address, vm_count_t length,
    int file, int exec_flag,
    vm_count_t page_size, void *buffer, vm_count_t buflen)
{
    vm_result_t result;
    Elf64_Ehdr *ehdr = buffer;
    Elf64_Phdr *phdr = 0;
    Elf64_Phdr load_phdr = { 0 };
    Elf64_Addr min_paddr = 0 != length ? guest_address : 0;
    Elf64_Half load_count = 0;
    vm_config_t config = { 0 };
    vm_mmap_t *map[1 + 2 * VM_LOAD_HEADER_MAXLEN / sizeof *phdr];
    size_t map_count = 0;

    /* check ELF header */
    if (sizeof*ehdr >  buflen ||
        127         != ehdr->e_ident[EI_MAG0] ||
        'E'         != ehdr->e_ident[EI_MAG1] ||
        'L'         != ehdr->e_ident[EI_MAG2] ||
        'F'         != ehdr->e_ident[EI_MAG3] ||
        ELFCLASS64  != ehdr->e_ident[EI_CLASS] ||
        ELFDATA2LSB != ehdr->e_ident[EI_DATA] ||
        EV_CURRENT  != ehdr->e_ident[EI_VERSION] ||
        (
            ET_EXEC != ehdr->e_type &&
            ET_DYN  != ehdr->e_type
        ) ||
#if (defined(_MSC_VER) && defined(_M_X64)) || (defined(__GNUC__) && defined(__x86_64__))
        EM_X86_64   != ehdr->e_machine ||
#elif (defined(_MSC_VER) && defined(_M_ARM64)) || (defined(__GNUC__) && defined(__aarch64__))
        EM_AARCH64  != ehdr->e_machine ||
#endif
        EV_CURRENT  != ehdr->e_version ||
        sizeof*ehdr != ehdr->e_ehsize ||
        0           != (ehdr->e_phoff & 7) ||
        VM_LOAD_HEADER_MAXLEN / sizeof *phdr
                    <  ehdr->e_phnum ||
        buflen      <  ehdr->e_phoff + ehdr->e_phentsize * ehdr->e_phnum)
    {
        result = vm_result(VM_ERROR_EXECFILE, 0);
        goto exit;
    }

    config.vcpu_entry = ehdr->e_entry;

    phdr = (Elf64_Phdr *)((char *)buffer + ehdr->e_phoff);

    /* mmap PT_LOAD segments */
    /*
     * ELF phdrs are sorted by p_vaddr, but we use p_paddr in this loader.
     * This means that we must sort the segments by p_paddr ourselves.
     */
    for (Elf64_Half j = 0, i; ehdr->e_phnum > j; j++)
    {
        /* find the next segment to load */
        for (i = 0; ehdr->e_phnum > i; i++)
            if (PT_LOAD == phdr[i].p_type && min_paddr <= (phdr[i].p_paddr & ~(page_size - 1)))
                break;
        if (ehdr->e_phnum == i)
            break;

        if ((phdr[i].p_offset & (page_size - 1)) != (phdr[i].p_paddr & (page_size - 1)) ||
            phdr[i].p_filesz > phdr[i].p_memsz ||
            phdr[i].p_filesz == 0)
        {
            result = vm_result(VM_ERROR_EXECFILE, 0);
            goto exit;
        }

        if (0 == load_count)
            config.exec_textseg = phdr[i].p_paddr;
        else
        if (1 == load_count)
            config.exec_dataseg = phdr[i].p_paddr;

        load_phdr.p_offset = phdr[i].p_offset & ~(page_size - 1);
        load_phdr.p_paddr = phdr[i].p_paddr & ~(page_size - 1);
        load_phdr.p_filesz = phdr[i].p_filesz + (phdr[i].p_paddr & (page_size - 1));
        load_phdr.p_memsz = ((phdr[i].p_paddr + phdr[i].p_memsz + page_size - 1) & ~(page_size - 1)) -
            load_phdr.p_paddr;

        if ((0 != length || 0 != min_paddr) && min_paddr < load_phdr.p_paddr)
        {
            /* fill hole between segments */
            result = vm_mmap(instance,
                min_paddr,
                load_phdr.p_paddr - min_paddr,
                0, -1,
                0,
                0,
                &map[map_count]);
            if (!vm_result_check(result))
                goto exit;
            map_count++;
        }

        /* load this segment */
        result = vm_mmap(instance,
            load_phdr.p_paddr,
            load_phdr.p_memsz,
            0, file,
            load_phdr.p_offset,
            load_phdr.p_filesz,
            &map[map_count]);
        if (!vm_result_check(result))
            goto exit;
        map_count++;

        min_paddr = load_phdr.p_paddr + load_phdr.p_memsz;
        load_count++;
    }

    if (0 != length && min_paddr < guest_address + length)
    {
        /* fill hole between segments */
        result = vm_mmap(instance,
            min_paddr,
            (guest_address + length) - min_paddr,
            0, -1,
            0,
            0,
            &map[map_count]);
        if (!vm_result_check(result))
            goto exit;
        map_count++;
    }

    if (exec_flag)
    {
        result = vm_reconfig(instance, &config,
            VM_CONFIG_BIT(vcpu_entry) |
            VM_CONFIG_BIT(exec_textseg) |
            VM_CONFIG_BIT(exec_dataseg));
        if (!vm_result_check(result))
            goto exit;
    }

    result = VM_RESULT_SUCCESS;

exit:
    if (!vm_result_check(result))
        for (size_t i = 0; map_count > i; i++)
            vm_munmap(instance, map[map_count]);

    return result;
}

vm_result_t vm_load(vm_t *instance,
    vm_count_t guest_address, vm_count_t length,
    int file, int exec_flag)
{
    vm_result_t result;
    vm_count_t page_size = (vm_count_t)getpagesize();
    char *buffer = 0;
    vm_count_t buflen;

    length = (length + page_size - 1) & ~(page_size - 1);
    if (0 != (guest_address & (page_size - 1)))
    {
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    buflen = VM_LOAD_HEADER_MAXLEN;
    buffer = malloc(buflen);
    if (0 == buffer)
    {
        result = vm_result(VM_ERROR_RESOURCES, 0);
        goto exit;
    }

    buflen = (vm_count_t)pread(file, buffer, buflen, 0);
    if (-1 == (ssize_t)buflen)
    {
        result = vm_result(VM_ERROR_FILE, errno);
        goto exit;
    }

    result = VM_ERROR_EXECFILE;
    if (4 <= buflen &&
        127 == buffer[0] && 'E' == buffer[1] && 'L' == buffer[2] && 'F' == buffer[3])
        result = vm_load_elf(instance, guest_address, length, file, exec_flag,
            page_size, buffer, buflen);
    if (!vm_result_check(result))
        goto exit;

    result = VM_RESULT_SUCCESS;

exit:
    free(buffer);

    return result;
}
