/**
 * @file xp/utility.h
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

#ifndef XP_UTILITY_H_INCLUDED
#define XP_UTILITY_H_INCLUDED

/*
 * bitsets
 */

typedef unsigned long long bset_t;

#define bset_declcount(capacity)        (((capacity) + bset__mask__() - 1) >> bset__shift__())
#define bset_capacity(bset)             (sizeof(bset) << 3)
#define bset__shift__()                 (6)
#define bset__mask__()                  (0x3f)

static inline
unsigned bset_get(bset_t *bset, unsigned pos)
{
#if defined(_MSC_VER)
    return _bittest64(&bset[pos >> bset__shift__()], pos & bset__mask__());
#elif defined(__GNUC__)
    return !!(bset[pos >> bset__shift__()] & ((bset_t)1 << (pos & bset__mask__())));
#endif
}

static inline
void bset_set(bset_t *bset, unsigned pos, unsigned val)
{
    if (val)
        bset[pos >> bset__shift__()] |= ((bset_t)1 << (pos & bset__mask__()));
    else
        bset[pos >> bset__shift__()] &= ~((bset_t)1 << (pos & bset__mask__()));
}

static inline
unsigned bset_popcount(bset_t *bset, unsigned capacity)
{
    unsigned res = 0;
    for (unsigned pos = 0, cnt = bset_declcount(capacity); cnt > pos; pos++)
    {
        bset_t bval = bset[pos];
#if defined(_MSC_VER)
        res += (unsigned)__popcnt64(bval);
#elif defined(__GNUC__)
        res += (unsigned)__builtin_popcountll(bval);
#endif
    }
    return res;
}

static inline
unsigned bset_find(bset_t *bset, unsigned capacity, unsigned val)
{
    for (unsigned idx = 0, cnt = bset_declcount(capacity); cnt > idx; idx++)
    {
        bset_t bval = val ? bset[idx] : ~bset[idx];
        unsigned bpos;
#if defined(_MSC_VER)
        if (_BitScanForward64(&bpos, bval))
            return (idx << bset__shift__()) | bpos;
#elif defined(__GNUC__)
        if (0 != (bpos = (unsigned)__builtin_ffsll((long long)bval)))
            return (idx << bset__shift__()) | (bpos - 1);
#endif
    }
    return ~0U;
}

/*
 * linked lists
 */

typedef struct list_link
{
    struct list_link *next, *prev;
} list_link_t;

static inline
void list_init(list_link_t *list)
{
    list->next = list;
    list->prev = list;
}

static inline
int list_is_empty(list_link_t *list)
{
    return list->next == list;
}

static inline
void list_insert_after(list_link_t *list, list_link_t *link)
{
    list_link_t *next = list->next;
    link->next = next;
    link->prev = list;
    next->prev = link;
    list->next = link;
}

static inline
void list_insert_before(list_link_t *list, list_link_t *link)
{
    list_link_t *prev = list->prev;
    link->next = list;
    link->prev = prev;
    prev->next = link;
    list->prev = link;
}

static inline
list_link_t *list_remove_after(list_link_t *list)
{
    list_link_t *link = list->next;
    list_link_t *next = link->next;
    list->next = next;
    next->prev = list;
    return link;
}

static inline
list_link_t *list_remove_before(list_link_t *list)
{
    list_link_t *link = list->prev;
    list_link_t *prev = link->prev;
    prev->next = list;
    list->prev = prev;
    return link;
}

static inline
void list_remove(list_link_t *link)
{
    list_link_t *next = link->next;
    list_link_t *prev = link->prev;
    next->prev = prev;
    prev->next = next;
}

#define list_traverse(i, dir, l)        \
    for (list_link_t *i = (l)->dir, *i##__list_temp__; i != (l); i = i##__list_temp__)\
        if (i##__list_temp__ = i->dir, 0) ; else

/*
 * string operations
 */

#define XP_UTILITY_STRCMP(NAME, TYPE, CONV)\
    static inline\
    int NAME(const TYPE *s, const TYPE *t)\
    {\
        int v = 0;\
        while (0 == (v = (int)(CONV((unsigned)*s) - CONV((unsigned)*t))) && *t)\
            ++s, ++t;\
        return v;/*(0 < v) - (0 > v);*/\
    }
#define XP_UTILITY_STRNCMP(NAME, TYPE, CONV)\
    static inline\
    int NAME(const TYPE *s, const TYPE *t, size_t n)\
    {\
        int v = 0;\
        const void *e = t + n;\
        while (e > (const void *)t && 0 == (v = (int)(CONV((unsigned)*s) - CONV((unsigned)*t))) && *t)\
            ++s, ++t;\
        return v;/*(0 < v) - (0 > v);*/\
    }
static inline
unsigned invariant_toupper(unsigned c)
{
    return c - 'a' <= 'z' - 'a' ? c & ~0x20U : c;
}
XP_UTILITY_STRCMP(invariant_strcmp, char, )
XP_UTILITY_STRCMP(invariant_stricmp, char, invariant_toupper)
XP_UTILITY_STRNCMP(invariant_strncmp, char, )
XP_UTILITY_STRNCMP(invariant_strnicmp, char, invariant_toupper)
#undef XP_UTILITY_STRCMP
#undef XP_UTILITY_STRNCMP

#define XP_UTILITY_STRTOINT(NAME, CTYPE, ITYPE)\
    static inline\
    ITYPE NAME(const CTYPE *p, CTYPE **endp, int base)\
    {\
        ITYPE v;\
        int maxdig, maxalp, sign = +1;\
        if (0 > base)\
        {\
            base = -base;\
            if ('+' == *p)\
                p++;\
            else if ('-' == *p)\
                p++, sign = -1;\
        }\
        if (2 > base)\
        {\
            if ('0' == *p)\
            {\
                p++;\
                if ('x' == *p || 'X' == *p)\
                {\
                    p++;\
                    base = 16;\
                }\
                else\
                    base = 8;\
            }\
            else\
            {\
                base = 10;\
            }\
        }\
        maxdig = 10 < base ? '9' : (base - 1) + '0';\
        maxalp = 10 < base ? (base - 1 - 10) + 'a' : 0;\
        for (v = 0; *p; p++)\
        {\
            int c = *p;\
            if ('0' <= c && c <= maxdig)\
                v = (ITYPE)base * v + (ITYPE)(c - '0');\
            else\
            {\
                c |= 0x20;\
                if ('a' <= c && c <= maxalp)\
                    v = (ITYPE)base * v + (ITYPE)(c - 'a') + 10;\
                else\
                    break;\
            }\
        }\
        if (0 != endp)\
            *endp = (CTYPE *)p;\
        return (ITYPE)sign * v;\
    }
XP_UTILITY_STRTOINT(strtoullint, char, unsigned long long int)
#undef XP_UTILITY_STRTOINT

#endif
