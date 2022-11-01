/**
 * @file arch/arch.h
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

#ifndef ARCH_ARCH_H_INCLUDED
#define ARCH_ARCH_H_INCLUDED

#if defined(_MSC_VER)
#define ARCH_PACKED(...)                __pragma(pack(push, 1)) __VA_ARGS__ __pragma(pack(pop))
#elif defined(__GNUC__)
#define ARCH_PACKED(...)                __VA_ARGS__ __attribute__((__packed__))
#endif

typedef unsigned char arch_u8_t;
typedef unsigned short arch_u16_t;
typedef unsigned int arch_u32_t;
typedef unsigned long long arch_u64_t;

#if (defined(_MSC_VER) && defined(_M_X64)) || (defined(__GNUC__) && defined(__x86_64__))
#include <arch/x64.h>
#else
#error unknown architecture
#endif

#endif
