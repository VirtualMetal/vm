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
};
ARCH_STATIC_ASSERT(8 == sizeof(struct arch_x64_seg_desc));

/* system segment descriptor - [INT 7.2.3], [AMD 4.8.3] */
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
};
ARCH_STATIC_ASSERT(16 == sizeof(struct arch_x64_sseg_desc));

/* gate descriptor - [INT 7.2.3], [AMD 4.8.4] */
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
};
ARCH_STATIC_ASSERT(16 == sizeof(struct arch_x64_gate_desc));

/* global descriptor table - layout compatible with linux boot protocol */
struct arch_x64_gdt
{
    struct arch_x64_seg_desc null;      /* cacheline */
    struct arch_x64_seg_desc reserved;
    struct arch_x64_seg_desc km_cs;
    struct arch_x64_seg_desc km_ds;
    struct arch_x64_sseg_desc tss;
    struct arch_x64_seg_desc um_cs;
    struct arch_x64_seg_desc um_ds;
};
ARCH_STATIC_ASSERT(64 == sizeof(struct arch_x64_gdt));

/* task state segment - [INT 7.7], [AMD 12.2.5] */
struct arch_x64_tss
{
    arch_u32_t reserved0[1];            /* cacheline */
    arch_u32_t rsp[3][2];
    arch_u32_t reserved1[2];
    arch_u32_t ist[7][2];
    arch_u32_t reserved2[2];
    arch_u16_t reserved3[1];
    arch_u16_t iopb;
};
ARCH_STATIC_ASSERT(104 == sizeof(struct arch_x64_tss));

/* interrupt descriptor table - [INT 6.3], [AMD 8.2] */
struct arch_x64_idt
{
    struct arch_x64_gate_desc desc[256];
};
ARCH_STATIC_ASSERT(4096 == sizeof(struct arch_x64_idt));

/* CPU data */
struct arch_x64_cpu_data
{
    ARCH_ALIGN(64) arch_u64_t km_stack[488];
    ARCH_ALIGN(64) struct arch_x64_gdt gdt;
    ARCH_ALIGN(64) struct arch_x64_tss tss;
    arch_u64_t data[3];
};
ARCH_STATIC_ASSERT(4096 == sizeof(struct arch_x64_cpu_data));

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

static inline
void arch_x64_cpu_data_init(struct arch_x64_cpu_data *cpu_data, arch_u64_t address)
{
    arch_u64_t offset;

    arch_x64_gdt_init(&cpu_data->gdt);
    arch_x64_tss_init(&cpu_data->tss);

    offset = (arch_u64_t)&((struct arch_x64_cpu_data *)0)->tss;
    cpu_data->gdt.tss.address0 = (arch_u32_t)((address + offset) & ((1 << 24) - 1));
    cpu_data->gdt.tss.address1 = (arch_u32_t)((address + offset) >> 24) & ((1 << 8) - 1);
    cpu_data->gdt.tss.address2 = (arch_u32_t)((address + offset) >> 32);

    offset = (arch_u64_t)&((struct arch_x64_cpu_data *)0)->km_stack + sizeof cpu_data->km_stack;
    cpu_data->tss.rsp[0][0] = (arch_u32_t)(address + offset);
    cpu_data->tss.rsp[0][1] = (arch_u32_t)((address + offset) >> 32);

    cpu_data->data[0] = 0;
    cpu_data->data[1] = 0;
    cpu_data->data[2] = 0;
}

#endif
