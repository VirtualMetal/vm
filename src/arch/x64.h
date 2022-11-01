/**
 * @file arch/x64.h
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

#ifndef ARCH_X64_H_INCLUDED
#define ARCH_X64_H_INCLUDED

/*
 * See:
 *
 * - [INT] Intel 64 and IA-32 Architectures Software Developer’s Manual Volume 3:
 * System Programming Guide
 * - [AMD] AMD64 Architecture Programmer’s Manual Volume 2: System Programming
 */

/* segment descriptor - [INT 3.4.5], [AMD 4.8.1,4.8.2] */
ARCH_PACKED(
struct arch_x64_seg_desc
{
    union
    {
        struct
        {
            arch_u64_t limit0:16;
            arch_u64_t address0:24;
            arch_u64_t type:4;
            arch_u64_t s:1;
            arch_u64_t dpl:2;
            arch_u64_t p:1;
            arch_u64_t limit1:4;
            arch_u64_t avl:1;
            arch_u64_t l:1;
            arch_u64_t db:1;
            arch_u64_t g:1;
            arch_u64_t address1:8;
        };
        arch_u64_t value0;
    };
});

/* system segment descriptor - [INT 7.2.3], [AMD 4.8.3] */
ARCH_PACKED(
struct arch_x64_sseg_desc
{
    union
    {
        struct
        {
            arch_u64_t limit0:16;
            arch_u64_t address0:24;
            arch_u64_t type:4;
            arch_u64_t s:1;
            arch_u64_t dpl:2;
            arch_u64_t p:1;
            arch_u64_t limit1:4;
            arch_u64_t avl:1;
            arch_u64_t l:1;
            arch_u64_t db:1;
            arch_u64_t g:1;
            arch_u64_t address1:8;
        };
        arch_u64_t value0;
    };
    union
    {
        struct
        {
            arch_u64_t address2:32;
            arch_u64_t reserved:32;
        };
        arch_u64_t value1;
    };
});

/* gate descriptor - [INT 7.2.3], [AMD 4.8.4] */
ARCH_PACKED(
struct arch_x64_gate_desc
{
    union
    {
        struct
        {
            arch_u64_t address0:16;
            arch_u64_t selector:16;
            arch_u64_t ist:3;
            arch_u64_t zero:5;
            arch_u64_t type:4;
            arch_u64_t s:1;
            arch_u64_t dpl:2;
            arch_u64_t p:1;
            arch_u64_t address1:16;
        };
        arch_u64_t value0;
    };
    union
    {
        struct
        {
            arch_u64_t address2:32;
            arch_u64_t reserved:32;
        };
        arch_u64_t value1;
    };
});

ARCH_PACKED(
struct arch_x64_gdt
{
    struct arch_x64_seg_desc null;
    struct arch_x64_seg_desc reserved0;
    struct arch_x64_sseg_desc tss;
    struct arch_x64_seg_desc km_cs;
    struct arch_x64_seg_desc km_ds;
    struct arch_x64_seg_desc um_cs;
    struct arch_x64_seg_desc um_ds;
});

ARCH_PACKED(
struct arch_x64_tss
{
    arch_u32_t reserved0[1];
    arch_u64_t rsp[3];
    arch_u32_t reserved1[2];
    arch_u64_t ist[7];
    arch_u32_t reserved2[3];
    arch_u32_t iopb;
});

static inline
void arch_x64_gdt_init(struct arch_x64_gdt *gdt)
{
    *gdt = (struct arch_x64_gdt){ 0 };

    gdt->km_cs = (struct arch_x64_seg_desc){
        .limit0 = 0xffff,
        .limit1 = 0xf,
        .type = 0b1011,                 /* TYPE=(1,C=0,R=1,A=1) */
        .s = 1,                         /* S=1 (code/data) */
        .dpl = 0,                       /* DPL=0 (kernel-mode) */
        .p = 1,                         /* P=1 (present) */
        .l = 1,                         /* L=1 (long mode) */
    };

    gdt->km_ds = (struct arch_x64_seg_desc){
        .limit0 = 0xffff,
        .limit1 = 0xf,
        .type = 0b0011,                 /* TYPE=(0,E=0,W=1,A=1) */
        .s = 1,                         /* S=1 (code/data) */
        .dpl = 0,                       /* DPL=0 (kernel-mode) */
        .p = 1,                         /* P=1 (present) */
        .l = 1,                         /* L=1 (long mode) */
    };

    gdt->um_cs = (struct arch_x64_seg_desc){
        .limit0 = 0xffff,
        .limit1 = 0xf,
        .type = 0b1011,                 /* TYPE=(1,C=0,R=1,A=1) */
        .s = 1,                         /* S=1 (code/data) */
        .dpl = 3,                       /* DPL=3 (user-mode) */
        .p = 1,                         /* P=1 (present) */
        .l = 1,                         /* L=1 (long mode) */
    };

    gdt->um_ds = (struct arch_x64_seg_desc){
        .limit0 = 0xffff,
        .limit1 = 0xf,
        .type = 0b0011,                 /* TYPE=(0,E=0,W=1,A=1) */
        .s = 1,                         /* S=1 (code/data) */
        .dpl = 3,                       /* DPL=3 (user-mode) */
        .p = 1,                         /* P=1 (present) */
        .l = 1,                         /* L=1 (long mode) */
    };

    gdt->tss = (struct arch_x64_sseg_desc){
        .limit0 = sizeof(struct arch_x64_tss) - 1,
        .type = 9,                      /* TYPE=9 (64-bit available TSS) */
        .s = 0,                         /* S=0 (system) */
        .dpl = 0,                       /* DPL=0 (kernel-mode) */
        .p = 1,                         /* P=1 (present) */
    };
}

static inline
void arch_x64_tss_init(struct arch_x64_tss *tss)
{
    *tss = (struct arch_x64_tss){ 0 };

    tss->iopb = sizeof(struct arch_x64_tss);
}

#endif
