/**
 * @file vmlinux/serial.c
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

#include <vmlinux/plugin.h>

#define RBR                             0
#define THR                             8
#define IER                             1
#define IIR                             2
#define LCR                             3
#define MCR                             4
#define LSR                             5
#define MSR                             6
#define SCR                             7
#define DLL                             0
#define DLM                             1
#define IER_RDA                         0x01
#define IER_THRE                        0x02
#define IIR_NONE                        0x01
#define IIR_THRE                        0x02
#define IIR_RDA                         0x04
#define LCR_DLAB                        0x80
#define LSR_DR                          0x01
#define LSR_THRE                        0x20
#define LSR_TEMT                        0x40

struct serial
{
    int fd[2];
    ioapic_t *apic;
    vm_count_t irq;
#if defined(_WIN64)
    BOOL (WINAPI *ReadConsoleInputExA)(
        HANDLE hConsoleInput,
        PINPUT_RECORD lpBuffer,
        DWORD nLength,
        LPDWORD lpNumberOfEventsRead,
        USHORT wFlags);
    HANDLE output_event;
    HANDLE cancel_event;
#elif defined(__linux__)
    int output_event;
    int cancel_event;
#endif
    pthread_mutex_t mutex;
    pthread_cond_t cvar;
    pthread_t thread;
    uint8_t regs[8 + 1];
    uint8_t divl[2];
    unsigned
        has_mutex:1,
        has_cvar:1,
        has_thread:1;
};

static void *serial_thread(void *port0);

vm_result_t serial_create(int fd[2], ioapic_t *apic, vm_count_t irq, serial_t **pport)
{
    vm_result_t result;
    serial_t *port = 0;
    int error;

    *pport = 0;

    port = malloc(sizeof *port);
    if (0 == port)
    {
        result = vm_result(VM_ERROR_RESOURCES, 0);
        goto exit;
    }

    memset(port, 0, sizeof *port);
    port->fd[0] = fd[0];
    port->fd[1] = fd[1];
    port->apic = apic;
    port->irq = irq;
    port->regs[IIR] = IIR_NONE;
    port->regs[LSR] = LSR_THRE | LSR_TEMT;
#if defined(__linux__)
    port->output_event = port->cancel_event = -1;
#endif

#if defined(_WIN64)
    DWORD mode;
    if (GetConsoleMode((HANDLE)(UINT_PTR)port->fd[0], &mode))
    {
        port->ReadConsoleInputExA = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"),
            "ReadConsoleInputExA");
        if (0 == port->ReadConsoleInputExA)
        {
            result = vm_result(VM_ERROR_RESOURCES, 0);
            goto exit;
        }

        mode = 0;
        if (!SetConsoleMode((HANDLE)(UINT_PTR)port->fd[0], mode))
        {
            result = vm_result(VM_ERROR_RESOURCES, errno);
            goto exit;
        }
    }

    port->output_event = CreateEventW(0, FALSE, FALSE, 0);
    if (0 == port->output_event)
    {
        result = vm_result(VM_ERROR_RESOURCES, errno);
        goto exit;
    }

    port->cancel_event = CreateEventW(0, FALSE, FALSE, 0);
    if (0 == port->cancel_event)
    {
        result = vm_result(VM_ERROR_RESOURCES, errno);
        goto exit;
    }
#elif defined(__linux__)
    struct termios attr;
    if (-1 != tcgetattr(STDIN_FILENO, &attr))
    {
        cfmakeraw(&attr);
        if (-1 == tcsetattr(STDIN_FILENO, TCSAFLUSH, &attr))
        {
            result = vm_result(VM_ERROR_RESOURCES, errno);
            goto exit;
        }
    }

    port->output_event = eventfd(0, EFD_CLOEXEC);
    if (-1 == port->output_event)
    {
        result = vm_result(VM_ERROR_RESOURCES, errno);
        goto exit;
    }

    port->cancel_event = eventfd(0, EFD_CLOEXEC);
    if (-1 == port->cancel_event)
    {
        result = vm_result(VM_ERROR_RESOURCES, errno);
        goto exit;
    }
#endif

    error = pthread_mutex_init(&port->mutex, 0);
    if (0 != error)
    {
        result = vm_result(VM_ERROR_RESOURCES, error);
        goto exit;
    }
    port->has_mutex = 1;

    error = pthread_cond_init(&port->cvar, 0);
    if (0 != error)
    {
        result = vm_result(VM_ERROR_RESOURCES, error);
        goto exit;
    }
    port->has_cvar = 1;

    error = pthread_create(&port->thread, 0, serial_thread, port);
    if (0 != error)
    {
        result = vm_result(VM_ERROR_RESOURCES, error);
        goto exit;
    }
    port->has_thread = 1;

    *pport = port;
    result = VM_RESULT_SUCCESS;

exit:
    if (!vm_result_check(result) && 0 != port)
        serial_delete(port);

    return result;
}

vm_result_t serial_delete(serial_t *port)
{
    if (port->has_thread)
    {
#if defined(_WIN64)
        SetEvent(port->cancel_event);
#elif defined(__linux__)
        uint64_t v = 1;
        write(port->cancel_event, &v, sizeof v);
#endif
        pthread_join(port->thread, 0);
    }

    if (port->has_cvar)
        pthread_cond_destroy(&port->cvar);

    if (port->has_mutex)
        pthread_mutex_destroy(&port->mutex);

#if defined(_WIN64)
    if (0 != port->cancel_event)
        CloseHandle(port->cancel_event);

    if (0 != port->output_event)
        CloseHandle(port->output_event);
#elif defined(__linux__)
    if (-1 != port->cancel_event)
        close(port->cancel_event);

    if (-1 != port->output_event)
        close(port->output_event);
#endif

    free(port);

    return VM_RESULT_SUCCESS;
}

static void *serial_thread(void *port0)
{
    serial_t *port = port0;
    ssize_t n;
    uint8_t b, ier, thre;

    for (;;)
    {
#if defined(_WIN64)
        HANDLE handles[3];
        INPUT_RECORD input;
        DWORD count;
        handles[0] = port->cancel_event;
        handles[1] = (HANDLE)(UINT_PTR)port->fd[0];
        handles[2] = port->output_event;
        for (n = 0; 0 == n;)
            switch (WaitForMultipleObjects(3, handles, FALSE, INFINITE))
            {
            case WAIT_OBJECT_0 + 0:
                goto exit;
            case WAIT_OBJECT_0 + 1:
                for (;;)
                {
                    if (!port->ReadConsoleInputExA(handles[1], &input, 1, &count, 2/*CONSOLE_READ_NOWAIT*/))
                        goto exit;
                    if (0 == count)
                        break;
                    if (KEY_EVENT == input.EventType &&
                        input.Event.KeyEvent.bKeyDown && 0 != input.Event.KeyEvent.uChar.AsciiChar)
                    {
                        b = input.Event.KeyEvent.uChar.AsciiChar;
                        n = 1;
                        break;
                    }
                }
                break;
            case WAIT_OBJECT_0 + 2:
                goto loopend;
            }
    loopend:
#elif defined(__linux__)
        struct pollfd pollfd[3];
        sigset_t sigset;
        pollfd[0].events = POLLIN; pollfd[0].fd = port->cancel_event;
        pollfd[1].events = POLLIN; pollfd[1].fd = port->fd[0];
        pollfd[2].events = POLLIN; pollfd[2].fd = port->output_event;
        sigfillset(&sigset);
        for (n = 0; 0 == n;)
        {
            ppoll(pollfd, 3, 0, &sigset);
            if (pollfd[0].revents)
                goto exit;
            else if (pollfd[1].revents)
            {
                n = read(port->fd[0], &b, 1);
                if (-1 == n)
                    goto exit;
                if (0 == n)
                    continue;
            }
            else if (pollfd[2].revents)
                goto loopend;
        }
    loopend:
#endif
        if (0 < n)
        {
            pthread_mutex_lock(&port->mutex);
            ier = port->regs[IER] & IER_RDA;
            if (ier)
            {
                port->regs[RBR] = b;
                port->regs[LSR] |= LSR_DR;
                port->regs[IIR] = IIR_RDA;
            }
            pthread_mutex_unlock(&port->mutex);
        }
        else
        {
            pthread_mutex_lock(&port->mutex);
            ier = 0;
            thre = port->regs[LSR] & LSR_THRE;
            if (!thre)
            {
                b = port->regs[THR];
                port->regs[THR] = 0;
                port->regs[LSR] |= LSR_THRE;
                ier = port->regs[IER] & IER_THRE;
                if (ier)
                    port->regs[IIR] = IIR_THRE;
            }
            pthread_mutex_unlock(&port->mutex);

            if (!thre)
                write(port->fd[1], &b, 1);
        }

        if (ier)
        {
            ioapic_irq(port->apic, port->irq);
            pthread_mutex_lock(&port->mutex);
            while (IIR_NONE != port->regs[IIR])
                pthread_cond_wait(&port->cvar, &port->mutex);
            pthread_mutex_unlock(&port->mutex);
        }
    }

exit:
    return 0;
}

vm_result_t serial_io(serial_t *port, vm_count_t flags, vm_count_t address, void *buffer)
{
    address &= 7;

    pthread_mutex_lock(&port->mutex);

    uint8_t *regs = port->regs;
    switch (address)
    {
    case 0:
        if (regs[LCR] & LCR_DLAB)
        {
            regs = port->divl;
            goto default_case;
        }
        else if (VM_XMIO_RD == VM_XMIO_DIR(flags))
        {
            *(uint8_t *)buffer = regs[RBR];
            regs[RBR] = 0;
            regs[IIR] = IIR_NONE;
            regs[LSR] &= ~LSR_DR;
            pthread_cond_signal(&port->cvar);
        }
        else
        {
            regs[THR] = *(uint8_t *)buffer;
            regs[IIR] = IIR_NONE;
            regs[LSR] &= ~LSR_THRE;
            pthread_cond_signal(&port->cvar);
#if defined(_WIN64)
            SetEvent(port->output_event);
#elif defined(__linux__)
            uint64_t v = 1;
            write(port->output_event, &v, sizeof v);
#endif
        }
        break;
    case 1:
        if (regs[LCR] & LCR_DLAB)
            regs = port->divl;
        goto default_case;
    case IIR:
        if (VM_XMIO_RD == VM_XMIO_DIR(flags))
        {
            *(uint8_t *)buffer = regs[address];
            if (IIR_THRE == regs[IIR])
            {
                regs[IIR] = IIR_NONE;
                pthread_cond_signal(&port->cvar);
            }
        }
        break;
    case LSR: case MSR:
        if (VM_XMIO_RD == VM_XMIO_DIR(flags))
            *(uint8_t *)buffer = regs[address];
        break;
    default:
    default_case:
        if (VM_XMIO_RD == VM_XMIO_DIR(flags))
            *(uint8_t *)buffer = regs[address];
        else
            regs[address] = *(uint8_t *)buffer;
        break;
    }

    pthread_mutex_unlock(&port->mutex);

    return VM_RESULT_SUCCESS;
}
