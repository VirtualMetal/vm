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
#define ARCH_ALIGN(N)                   __declspec(align(N))
#define ARCH_PACK(...)                  __pragma(pack(push, 1)) __VA_ARGS__ __pragma(pack(pop))
#elif defined(__GNUC__)
#define ARCH_ALIGN(N)                   __attribute__((__aligned__(N)))
#define ARCH_PACK(...)                  __VA_ARGS__ __attribute__((__packed__))
#endif

#define ARCH_STATIC_ASSERT(E)           _Static_assert(E, #E)

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
