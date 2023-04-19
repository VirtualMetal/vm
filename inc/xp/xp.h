/**
 * @file xp/xp.h
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

#ifndef XP_XP_H_INCLUDED
#define XP_XP_H_INCLUDED

#if defined(_MSC_VER)
#elif defined(__GNUC__)
#else
#error unknown compiler
#endif

#if defined(_MSC_VER) && defined(_M_X64)
#elif defined(__GNUC__) && defined(__x86_64__)
#else
#error unknown architecture
#endif

#if defined(_WIN64)
#elif defined(__linux__)
#else
#error unknown platform
#endif

#include <xp/platform.h>
#include <xp/utility.h>

#endif
