/**
 * @file vm/gdb.c
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

#define PACKET_SIZE                     (16 * 1024)
#define MBUF_SIZE                       ((PACKET_SIZE - 4) / 2)

struct vm
{
    vm_config_t config;
};

struct vm_gdb_state
{
    vm_t *instance;
    vm_result_t (*strm)(void *strmdata, int dir, void *buffer, vm_count_t *plength);
    void *strmdata;
    char *ibuf, *obuf, *mbuf;
    int noack, is_attached, is_detached;
    int ctid, gtid;                     /* gdb thread-id == vcpu_index + 1 */
    int next_tid;
#if defined(_WIN64)
    LONG is_sendstop_enabled;
#else
    int is_sendstop_enabled;
#endif
};

static void vm_gdb_events_handler(void *self, vm_t *instance, vm_count_t control, vm_count_t reserved);
static vm_result_t vm_gdb_loop(struct vm_gdb_state *state);
static vm_result_t vm_gdb_packet(struct vm_gdb_state *state, char *packet);
static vm_result_t vm_gdb_xfer_read(struct vm_gdb_state *state, const char *annex, char *p);
static vm_result_t vm_gdb_sendbuf(struct vm_gdb_state *state);
static vm_result_t vm_gdb_sendempty(struct vm_gdb_state *state);
static vm_result_t vm_gdb_sendres(struct vm_gdb_state *state, int ok);
static vm_result_t vm_gdb_sendf(struct vm_gdb_state *state, char *format, ...);
static vm_result_t vm_gdb_sendstop_oob(struct vm_gdb_state *state, unsigned char signum);
static void hex_to_bin(char *p, unsigned char *q);
static void bin_to_hex(unsigned char *p, char *q);

vm_result_t vm_gdb(vm_t *instance,
    vm_result_t (*strm)(void *strmdata, int dir, void *buffer, vm_count_t *plength),
    void *strmdata)
{
    vm_result_t result;
    struct vm_gdb_state state;
    vm_debug_events_t debug_events;
    vm_count_t length;
    char *buffer = 0;

    buffer = malloc(PACKET_SIZE * 2 + MBUF_SIZE);
    if (0 == buffer)
    {
        result = vm_result(VM_ERROR_RESOURCES, 0);
        goto exit;
    }

    memset(&state, 0, sizeof state);
    state.instance = instance;
    state.strm = strm;
    state.strmdata = strmdata;
    state.ibuf = buffer;                    /* input buffer size is PacketSize */
    state.obuf = buffer + 1 * PACKET_SIZE;  /* output buffer size is PacketSize */
    state.mbuf = buffer + 2 * PACKET_SIZE;  /* memory buffer size is (PacketSize - 4) / 2 */
    state.is_attached = 1;
    state.ctid = state.gtid = 1;
    state.next_tid = 1;

    /* attach to debuggee upon connection (if not already attached) */
    result = vm_debug(instance, VM_DEBUG_ATTACH, 0, 0, 0);
    if (!vm_result_check(result))
    {
        if (VM_ERROR_MISUSE != vm_result_error(result))
            goto exit;
        /* if debugger already attached, then "qAttached" response is that we created new process */
        state.is_attached = 0;
    }
    if (!vm_result_check(result) && VM_ERROR_MISUSE != vm_result_error(result))
        goto exit;

    memset(&debug_events, 0, sizeof debug_events);
    debug_events.self = &state;
    debug_events.handler = vm_gdb_events_handler;
    length = sizeof debug_events;
    result = vm_debug(instance, VM_DEBUG_SETEVENTS, 0, &debug_events, &length);
    if (!vm_result_check(result))
        goto exit;

    /* stop the debuggee upon connection (if not already stopped) */
    result = vm_debug(instance, VM_DEBUG_BREAK, 0, 0, 0);
    if (!vm_result_check(result))
        goto exit;

    result = vm_gdb_loop(&state);

exit:
    vm_debug(instance, VM_DEBUG_SETEVENTS, 0, 0, 0);

    free(buffer);

    return result;
}

static void vm_gdb_events_handler(void *self, vm_t *instance, vm_count_t control, vm_count_t reserved)
{
    struct vm_gdb_state *state = self;

    switch (control)
    {
    case VM_DEBUG_BREAK:
#if defined(_WIN64)
        if (InterlockedCompareExchange(&state->is_sendstop_enabled, 0, 1))
#else
        int expected = 1;
        if (atomic_compare_exchange_strong(&state->is_sendstop_enabled, &expected, 0))
#endif
            vm_gdb_sendstop_oob(state, 5);
        break;

    case VM_DEBUG_CONT:
#if defined(_WIN64)
        InterlockedExchange(&state->is_sendstop_enabled, 1);
#else
        atomic_store(&state->is_sendstop_enabled, 1);
#endif
        break;
    }
}

static vm_result_t vm_gdb_loop(struct vm_gdb_state *state)
{
    vm_result_t result;
    char *p, *ibufp, *packp;
    vm_count_t length;
    unsigned char pack_sum, want_sum;
    char ack[1];

    for (;;)
    {
    refill:
        ibufp = p = state->ibuf;
        packp = 0;

    fill:
        length = (vm_count_t)(state->ibuf + PACKET_SIZE - ibufp);
        if (0 == length)
        {
            if (0 == packp || state->ibuf == packp)
                /* if there is no packet or packet is too large, discard and refill */
                goto refill;
            memmove(state->ibuf, packp, (size_t)(ibufp - packp));
            p -= packp - state->ibuf;
            ibufp -= packp - state->ibuf;
            length = (vm_count_t)(state->ibuf + PACKET_SIZE - ibufp);
        }
        result = state->strm(state->strmdata, +1, ibufp, &length);
        if (!vm_result_check(result) || 0 == length)
            goto exit;
        ibufp += length;

    parse:
        if (0 == packp)
        {
            for (;;)
            {
                if (ibufp == p)
                    goto refill;
                else if ('$' == *p)
                    /* found packet start */
                    break;
                else if ('\x03' == *p)
                    /* interrupt: issue debug break */
                    vm_debug(state->instance, VM_DEBUG_BREAK, 0, 0, 0);
                p++;
            }
            packp = p++;
            pack_sum = 0;
        }

        for (;;)
        {
            if (ibufp == p)
                goto fill;
            else if ('#' == *p)
                /* found packet end */
                break;
            pack_sum += (unsigned char)*p++;
        }

        if (ibufp < p + 3)
            goto fill;
        hex_to_bin(p + 1, &want_sum);

        if (!state->noack)
        {
            ack[0] = pack_sum == want_sum ? '+' : '-';
            length = sizeof ack;
            result = state->strm(state->strmdata, -1, ack, &length);
            if (!vm_result_check(result))
                break;
        }

        if (pack_sum == want_sum)
        {
            *p = '\0';
            result = vm_gdb_packet(state, packp + 1);
            if (!vm_result_check(result) || state->is_detached)
                break;
        }

        p += 3;
        packp = 0;
        goto parse;
    }

exit:
    return result;
}

static vm_result_t vm_gdb_packet(struct vm_gdb_state *state, char *packet)
{
    vm_result_t result = VM_RESULT_SUCCESS;
    vm_count_t address, length;
    char *p, *endp, *q, *endq;
    int ok;

    switch (packet[0])
    {
    case '?': /* query */
        result = vm_gdb_sendf(state, "S%02x", 5);
        break;

    case 'c': /* continue */
    case 'C': /* continue with signal */
        vm_debug(state->instance, VM_DEBUG_CONT, 0, 0, 0);
        break;

    case 's': /* step */
    case 'S': /* step with signal */
        vm_debug(state->instance, VM_DEBUG_STEP, (vm_count_t)(state->ctid - 1), 0, 0);
        break;

    case 'D': /* detach */
        vm_debug(state->instance, VM_DEBUG_SETEVENTS, 0, 0, 0);
        vm_debug(state->instance, VM_DEBUG_BREAK, 0, 0, 0);
        vm_debug(state->instance, VM_DEBUG_DETACH, 0, 0, 0);
        state->is_detached = 1;
        result = vm_gdb_sendres(state, 1);
        break;

    case 'g': /* read registers */
        length = MBUF_SIZE;
        ok = vm_result_check(
            vm_debug(state->instance, VM_DEBUG_GETREGS, (vm_count_t)(state->gtid - 1),
                state->mbuf, &length));
        if (ok)
        {
            for (p = state->mbuf, endp = p + length, q = state->obuf + 1; endp > p; p++, q += 2)
                bin_to_hex(p, q);
            *q = '\0';
            ok = 1;
            result = vm_gdb_sendbuf(state);
        }
        if (!ok)
            result = vm_gdb_sendres(state, 0);
        break;

    case 'G': /* write registers */
        ok = 0;
        p = packet + 1;
        endq = state->mbuf + MBUF_SIZE;
        for (q = state->mbuf; endq > q && p[0] && p[1]; p += 2, q++)
            hex_to_bin(p, q);
        length = (vm_count_t)(q - state->mbuf);
        ok = vm_result_check(
            vm_debug(state->instance, VM_DEBUG_SETREGS, (vm_count_t)(state->gtid - 1),
                state->mbuf, &length));
        result = vm_gdb_sendres(state, ok);
        break;

    case 'H': /* set thread */
        ok = 0;
        if ('c' == packet[1])
        {
            int ctid = (int)strtoullint(packet + 2, 0, -16);
            if (0 >= ctid)
                /* we can only continue ALL threads and we can only step ONE thread */
                ctid = 1;
            ok = ctid <= state->instance->config.vcpu_count;
            if (ok)
                state->ctid = ctid;
        }
        else if ('g' == packet[1])
        {
            int gtid = (int)strtoullint(packet + 2, 0, -16);
            if (0 >= gtid)
                /* we can only get/set registers for ONE thread */
                gtid = 1;
            ok = gtid <= state->instance->config.vcpu_count;
            if (ok)
                state->gtid = gtid;
        }
        result = vm_gdb_sendres(state, ok);
        break;

    case 'k': /* kill */
        vm_terminate(state->instance);
        result = VM_ERROR_TERMINATED;
        break;

    case 'm': /* read memory */
        ok = 0;
        address = strtoullint(packet + 1, &p, 16);
        if (',' == *p)
        {
            length = strtoullint(p + 1, &p, 16);
            if ('\0' == *p && 0 < length && length <= MBUF_SIZE)
            {
                vm_mread(state->instance, address, state->mbuf, &length);
                for (p = state->mbuf, endp = p + length, q = state->obuf + 1; endp > p; p++, q += 2)
                    bin_to_hex(p, q);
                *q = '\0';
                ok = 1;
                result = vm_gdb_sendbuf(state);
            }
        }
        if (!ok)
            result = vm_gdb_sendres(state, 0);
        break;

    case 'M': /* write memory */
        ok = 0;
        address = strtoullint(packet + 1, &p, 16);
        if (',' == *p)
        {
            length = strtoullint(p + 1, &p, 16);
            if (':' == *p)
            {
                vm_count_t written;
                endq = state->mbuf + MBUF_SIZE;
                p++;
                for (q = state->mbuf; endq > q && p[0] && p[1]; p += 2, q++)
                    hex_to_bin(p, q);
                written = (vm_count_t)(q - state->mbuf);
                vm_mwrite(state->instance, state->mbuf, address, &written);
                ok = written == length;
            }
        }
        result = vm_gdb_sendres(state, ok);
        break;

    case 'q': /* general query */
        if (0 == invariant_strncmp(packet + 1, "Attached", sizeof "Attached" - 1))
            result = vm_gdb_sendf(state, "%d", state->is_attached);
        else if (0 == invariant_strncmp(packet + 1, "C", sizeof "C" - 1))
            result = vm_gdb_sendf(state, "QC%d", state->gtid);
        else
        if (0 == invariant_strncmp(packet + 1, "fThreadInfo", sizeof "fThreadInfo" - 1) ||
            0 == invariant_strncmp(packet + 1, "sThreadInfo", sizeof "sThreadInfo" - 1))
        {
            if ('f' == packet[1])
                state->next_tid = 1;
            if (state->next_tid <= state->instance->config.vcpu_count)
            {
                int last_tid = state->next_tid + 256;
                if (last_tid > state->instance->config.vcpu_count)
                    last_tid = (int)state->instance->config.vcpu_count;
                p = state->obuf + 1;
                for (int f = 1; last_tid >= state->next_tid; state->next_tid++, f = 0)
                {
                    sprintf(p, "%s%x", f ? "m" : ",", state->next_tid);
                    p += strlen(p);
                }
                result = vm_gdb_sendbuf(state);
            }
            else
                result = vm_gdb_sendf(state, "l");
        }
        else
        if (0 == invariant_strncmp(packet + 1, "Offsets", sizeof "Offsets" - 1))
            result = vm_gdb_sendf(state,
                "Text=0;Data=0;Bss=0");
        else
        if (0 == invariant_strncmp(packet + 1, "Supported", sizeof "Supported" - 1))
            result = vm_gdb_sendf(state,
                "PacketSize=%d;QStartNoAckMode+;swbreak+;qXfer:features:read+",
                PACKET_SIZE);
        else
        if (0 == invariant_strncmp(packet + 1, "Xfer:features:read:", sizeof "Xfer:features:read:" - 1))
        {
            p = packet + sizeof "Xfer:features:read:";
            if (0 == invariant_strncmp(p, "target.xml:", sizeof "target.xml:" - 1))
            {
                /*
                 * This must be already in binary data representation.
                 * See https://sourceware.org/gdb/onlinedocs/gdb/Overview.html#Binary-Data
                 */
                static char target_xml[] =
                    "<target version=\"1.0\"><architecture>"
#if (defined(_MSC_VER) && defined(_M_X64)) || (defined(__GNUC__) && defined(__x86_64__))
                    "i386:x86-64"
#endif
                    "</architecture></target>";
                p += sizeof "target.xml:" - 1;
                result = vm_gdb_xfer_read(state, target_xml, p);
            }
            else
                result = vm_gdb_sendf(state, "E00");
        }
        else
            goto unrecognized;
        break;

    case 'Q': /* general set */
        if (0 == invariant_strncmp(packet + 1, "StartNoAckMode", sizeof "StartNoAckMode" - 1))
        {
            state->noack = 1;
            result = vm_gdb_sendres(state, 1);
        }
        else
            goto unrecognized;
        break;

    case 'z': /* remove breakpoint/watchpoint */
    case 'Z': /* insert breakpoint/watchpoint */
        if ('0' == packet[1])
        {
            ok = 0;
            p = packet + 2;
            if (',' == *p)
            {
                address = strtoullint(p + 1, &p, +16);
                if (',' == *p)
                {
                    length = sizeof address;
                    ok = vm_result_check(
                        vm_debug(state->instance, 'Z' == packet[0] ? VM_DEBUG_SETBP : VM_DEBUG_DELBP,
                            0, &address, &length));
                }
            }
            result = vm_gdb_sendres(state, ok);
        }
        else
            goto unrecognized;
        break;

    default: /* unrecognized command */
    unrecognized:
        result = vm_gdb_sendempty(state);
        break;
    }

    return result;
}

static vm_result_t vm_gdb_xfer_read(struct vm_gdb_state *state, const char *annex, char *p)
{
    vm_result_t result;
    size_t offset, end_offset,length, annex_length;
    int ok;

    annex_length = strlen(annex);

    ok = 0;
    offset = strtoullint(p, &p, 16);
    if (',' == *p)
    {
        length = strtoullint(p + 1, &p, 16);
        if ('\0' == *p && offset <= annex_length)
        {
            end_offset = offset + length;
            if (end_offset > annex_length)
                end_offset = annex_length;
            length = end_offset - offset;
            if (length <= MBUF_SIZE)
            {
                state->obuf[1] = 'l';
                memcpy(state->obuf + 2, annex + offset, length);
                state->obuf[2 + length] = '\0';
                ok = 1;
                result = vm_gdb_sendbuf(state);
            }
        }
    }
    if (!ok)
        result = vm_gdb_sendres(state, 0);

    return result;
}

static vm_result_t vm_gdb_sendbuf(struct vm_gdb_state *state)
{
    vm_result_t result;
    vm_count_t length;
    unsigned char pack_sum;

    state->obuf[0] = '$';
    length = strlen(state->obuf + 1);

    pack_sum = 0;
    for (char *p = state->obuf + 1, *endp = p + length; endp > p; p++)
        pack_sum += (unsigned char)*p;

    state->obuf[1 + length] = '#';
    bin_to_hex(&pack_sum, state->obuf + 2 + length);

    length += 4;
    result = state->strm(state->strmdata, -1, state->obuf, &length);

    return result;
}

static vm_result_t vm_gdb_sendempty(struct vm_gdb_state *state)
{
    vm_result_t result;

    state->obuf[1] = '\0';
    result = vm_gdb_sendbuf(state);

    return result;
}

static vm_result_t vm_gdb_sendres(struct vm_gdb_state *state, int ok)
{
    vm_result_t result;

    if (ok)
    {
        state->obuf[1] = 'O';
        state->obuf[2] = 'K';
        state->obuf[3] = '\0';
    }
    else
    {
        state->obuf[1] = 'E';
        state->obuf[2] = '0';
        state->obuf[3] = '1';
        state->obuf[4] = '\0';
    }
    result = vm_gdb_sendbuf(state);

    return result;
}

static vm_result_t vm_gdb_sendf(struct vm_gdb_state *state, char *format, ...)
{
    vm_result_t result;
    va_list ap;

    va_start(ap, format);

    vsprintf(state->obuf + 1, format, ap);
    result = vm_gdb_sendbuf(state);

    va_end(ap);

    return result;
}

static vm_result_t vm_gdb_sendstop_oob(struct vm_gdb_state *state, unsigned char signum)
{
    /*
     * Send a stop "out-of-band".
     *
     * This function uses a private output buffer and sends it using a special
     * "out-of-band" mode. This makes it safe for use for threads other than the
     * main GDB server thread.
     */

    vm_result_t result;
    char buf[7];
    vm_count_t length;
    unsigned char pack_sum;

    buf[0] = '$';
    buf[1] = 'S';
    bin_to_hex(&signum, buf + 2);
    buf[4] = '#';

    pack_sum = 0;
    pack_sum += (unsigned char)buf[1];
    pack_sum += (unsigned char)buf[2];
    pack_sum += (unsigned char)buf[3];
    bin_to_hex(&pack_sum, buf + 5);

    length = sizeof buf;
    result = state->strm(state->strmdata, -2, buf, &length);

    return result;
}

static void hex_to_bin(char *p, unsigned char *q)
{
    *q = 0;
    for (int i = 0; 2 > i; i++)
    {
        int c = p[i];
        if ('0' <= c && c <= '9')
            *q = (unsigned char)(*q << 4) | (unsigned char)(c - '0');
        else
        {
            c |= 0x20;
            if ('a' <= c && c <= 'f')
                *q = (unsigned char)(*q << 4) | (unsigned char)(c - 'a' + 10);
        }
    }
}

static void bin_to_hex(unsigned char *p, char *q)
{
    static char hex[] = "0123456789abcdef";
    q[0] = hex[*p >> 4];
    q[1] = hex[*p & 15];
}
