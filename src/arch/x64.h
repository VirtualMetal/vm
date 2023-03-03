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
 * - [INT] Intel 64 and IA-32 Architectures Software Developers Manual Volume 3:
 * System Programming Guide
 * - [AMD] AMD64 Architecture Programmers Manual Volume 2: System Programming
 * - [ACPI] Advanced Configuration and Power Interface (ACPI) Specification Release 6.4
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

/* system segment descriptor - [INT 8.2.3], [AMD 4.8.3] */
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

/* gate descriptor - [INT 6.14.1], [AMD 4.8.4] */
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

/* task state segment - [INT 8.7], [AMD 12.2.5] */
struct arch_x64_tss
{
    arch_u32_t reserved0[1];            /* cacheline */
    arch_u32_t rsp[3][2];
    arch_u32_t ist[8][2];               /* ist[0] is reserved/unused */
    arch_u32_t reserved1[2];
    arch_u16_t reserved2[1];
    arch_u16_t iopb;
};
ARCH_STATIC_ASSERT(104 == sizeof(struct arch_x64_tss));

/* interrupt descriptor table - [INT 6.3], [AMD 8.2] */
struct arch_x64_idt
{
    struct arch_x64_gate_desc desc[256];
};
ARCH_STATIC_ASSERT(4096 == sizeof(struct arch_x64_idt));

/* wakeup wait - [ACPI 5.2.12.19] */
struct arch_x64_wakeup
{
    arch_u8_t code[24];
};
ARCH_STATIC_ASSERT(24 == sizeof(struct arch_x64_wakeup));

/* CPU data */
struct arch_x64_cpu_data
{
    ARCH_ALIGN(64) arch_u64_t km_stack[488];
    ARCH_ALIGN(64) struct arch_x64_gdt gdt;
    ARCH_ALIGN(64) struct arch_x64_tss tss;
    struct arch_x64_wakeup wakeup;
};
ARCH_STATIC_ASSERT(4096 == sizeof(struct arch_x64_cpu_data));

static inline
void arch_x64_intg_init(struct arch_x64_gate_desc *gate, arch_u64_t address, arch_u8_t ist)
{
    arch_u16_t selector = (arch_u16_t)(arch_u64_t)&((struct arch_x64_gdt *)0)->km_cs;

    *gate = (struct arch_x64_gate_desc){
        .selector = selector,
        .address0 = (arch_u16_t)((address) & 0xffff),
        .address1 = (arch_u16_t)((address >> 16) & 0xffff),
        .address2 = (arch_u32_t)((address >> 32) & 0xffffffff),
        .ist = (arch_u8_t)(ist & 7),
        .type = 14,                     /* TYPE=14 (64-bit Interrupt Gate) */
        .dpl = 0,                       /* DPL=0 (kernel-mode) */
        .p = 1,                         /* P=1 (present) */
    };
}

static inline
void arch_x64_sysg_init(struct arch_x64_gate_desc *gate, arch_u64_t address, arch_u8_t ist)
{
    arch_u16_t selector = (arch_u16_t)(arch_u64_t)&((struct arch_x64_gdt *)0)->km_cs;

    *gate = (struct arch_x64_gate_desc){
        .selector = selector,
        .address0 = (arch_u16_t)((address) & 0xffff),
        .address1 = (arch_u16_t)((address >> 16) & 0xffff),
        .address2 = (arch_u32_t)((address >> 32) & 0xffffffff),
        .ist = (arch_u8_t)(ist & 7),
        .type = 14,                     /* TYPE=14 (64-bit Interrupt Gate) */
        .dpl = 3,                       /* DPL=3 (user-mode) */
        .p = 1,                         /* P=1 (present) */
    };
}

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
        .g = 1,                         /* G=1 (ignored in long mode) */
    };

    gdt->km_ds = (struct arch_x64_seg_desc){
        .limit0 = 0xffff,
        .limit1 = 0xf,
        .type = 0b0011,                 /* TYPE=(0,E=0,W=1,A=1) */
        .s = 1,                         /* S=1 (code/data) */
        .dpl = 0,                       /* DPL=0 (kernel-mode) */
        .p = 1,                         /* P=1 (present) */
        .l = 1,                         /* L=1 (long mode) */
        .g = 1,                         /* G=1 (ignored in long mode) */
    };

    gdt->um_cs = (struct arch_x64_seg_desc){
        .limit0 = 0xffff,
        .limit1 = 0xf,
        .type = 0b1011,                 /* TYPE=(1,C=0,R=1,A=1) */
        .s = 1,                         /* S=1 (code/data) */
        .dpl = 3,                       /* DPL=3 (user-mode) */
        .p = 1,                         /* P=1 (present) */
        .l = 1,                         /* L=1 (long mode) */
        .g = 1,                         /* G=1 (ignored in long mode) */
    };

    gdt->um_ds = (struct arch_x64_seg_desc){
        .limit0 = 0xffff,
        .limit1 = 0xf,
        .type = 0b0011,                 /* TYPE=(0,E=0,W=1,A=1) */
        .s = 1,                         /* S=1 (code/data) */
        .dpl = 3,                       /* DPL=3 (user-mode) */
        .p = 1,                         /* P=1 (present) */
        .l = 1,                         /* L=1 (long mode) */
        .g = 1,                         /* G=1 (ignored in long mode) */
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
void arch_x64_wakeup_init(struct arch_x64_wakeup *wakeup)
{
    *wakeup = (struct arch_x64_wakeup)
        {
            .code =
                "\xF3\x90"              /* spin:    pause */
                "\x48\x39\x37"          /*          cmp [rdi],rsi */
                "\x75\xF9"              /*          jne spin */
                "\x31\xF6"              /*          xor esi,esi */
                "\x48\x8B\x47\x08"      /*          mov rax,[rdi+8] */
                "\x48\x87\x37"          /*          xchg [rdi],rsi */
                "\xFF\xE0"              /*          jmp rax */
        };
}

static inline
void arch_x64_cpu_data_init(struct arch_x64_cpu_data *cpu_data, arch_u64_t address)
{
    arch_u64_t offset;

    arch_x64_gdt_init(&cpu_data->gdt);
    arch_x64_tss_init(&cpu_data->tss);
    arch_x64_wakeup_init(&cpu_data->wakeup);

    offset = (arch_u64_t)&((struct arch_x64_cpu_data *)0)->tss;
    cpu_data->gdt.tss.address0 = (arch_u32_t)((address + offset) & ((1 << 24) - 1));
    cpu_data->gdt.tss.address1 = (arch_u32_t)((address + offset) >> 24) & ((1 << 8) - 1);
    cpu_data->gdt.tss.address2 = (arch_u32_t)((address + offset) >> 32);

    offset = (arch_u64_t)&((struct arch_x64_cpu_data *)0)->km_stack + sizeof cpu_data->km_stack;
    cpu_data->tss.rsp[0][0] = cpu_data->tss.ist[1][0] = (arch_u32_t)(address + offset);
    cpu_data->tss.rsp[0][1] = cpu_data->tss.ist[1][1] = (arch_u32_t)((address + offset) >> 32);
}

#endif
