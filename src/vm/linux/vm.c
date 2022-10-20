/**
 * @file vm/linux/vm.c
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

#include <vm/vm.h>
#include <vm/internal.h>
#include <linux/kvm.h>

struct vm
{
    vm_config_t config;
    int hv_fd;
    int vm_fd;
    int cpu_run_size;
    void *memory;
    unsigned debug_log_flags;
    pthread_mutex_t cancel_lock;
    pthread_barrier_t barrier;
    pthread_t thread;                   /* protected by cancel_lock */
    vm_count_t thread_count;
    vm_result_t thread_result;
    unsigned
        is_cancelled:1,                 /* protected by cancel_lock */
        has_cancel_lock:1,
        has_barrier:1,
        has_memory_region:1,
        has_thread:1;                   /* protected by cancel_lock */
};

static void *vm_thread(void *instance0);
static void vm_thread_signal(int signum);
static vm_result_t vm_cpuexit_unknown(vm_t *instance, struct kvm_run *cpu_run);
static vm_result_t vm_cpuexit_MMIO(vm_t *instance, struct kvm_run *cpu_run);
static vm_result_t vm_cpuexit_IO(vm_t *instance, struct kvm_run *cpu_run);
static void vm_debug_log(unsigned cpu_index, struct kvm_run *cpu_run, vm_result_t result);

#define SIGCANCEL                       SIGUSR1

vm_result_t vm_create(const vm_config_t *config, vm_t **pinstance)
{
    vm_result_t result;
    vm_t *instance = 0;
    int error;

    *pinstance = 0;

    instance = malloc(sizeof *instance);
    if (0 == instance)
    {
        result = VM_ERROR_MEMORY;
        goto exit;
    }

    memset(instance, 0, sizeof *instance);
    instance->config = *config;
    instance->hv_fd = -1;
    instance->vm_fd = -1;
    instance->memory = MAP_FAILED;

    if (0 == instance->config.cpu_count)
    {
        cpu_set_t affinity;
        CPU_ZERO(&affinity);
        if (-1 == sched_getaffinity(0, sizeof affinity, &affinity))
        {
            result = vm_result(VM_ERROR_HYPERVISOR, errno);
            goto exit;
        }
        instance->config.cpu_count = (vm_count_t)CPU_COUNT(&affinity);
    }
    if (0 == instance->config.cpu_count)
        instance->config.cpu_count = 1;

    error = pthread_mutex_init(&instance->cancel_lock, 0);
    if (0 != error)
    {
        result = vm_result(VM_ERROR_MEMORY, error);
        goto exit;
    }
    instance->has_cancel_lock = 1;

    error = pthread_barrier_init(&instance->barrier, 0, 2);
    if (0 != error)
    {
        result = vm_result(VM_ERROR_MEMORY, error);
        goto exit;
    }
    instance->has_barrier = 1;

    instance->hv_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (-1 == instance->hv_fd)
    {
        result = vm_result(VM_ERROR_HYPERVISOR, errno);
        goto exit;
    }

    if (12 != ioctl(instance->hv_fd, KVM_GET_API_VERSION, NULL))
    {
        result = VM_ERROR_HYPERVISOR;
        goto exit;
    }

    if (0 >= ioctl(instance->hv_fd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY) ||
        0 >= ioctl(instance->hv_fd, KVM_CHECK_EXTENSION, KVM_CAP_IMMEDIATE_EXIT))
    {
        result = VM_ERROR_HYPERVISOR;
        goto exit;
    }

    instance->cpu_run_size = ioctl(instance->hv_fd, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (-1 == instance->cpu_run_size)
    {
        result = vm_result(VM_ERROR_HYPERVISOR, errno);
        goto exit;
    }

    instance->vm_fd = ioctl(instance->hv_fd, KVM_CREATE_VM, NULL);
    if (-1 == instance->vm_fd)
    {
        result = vm_result(VM_ERROR_INSTANCE, errno);
        goto exit;
    }

    instance->memory = mmap(
        0, instance->config.memory_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (MAP_FAILED == instance->memory)
    {
        result = vm_result(VM_ERROR_MEMORY, errno);
        goto exit;
    }

    struct kvm_userspace_memory_region region;
    memset(&region, 0, sizeof region);
    region.guest_phys_addr = 0;
    region.memory_size = instance->config.memory_size;
    region.userspace_addr = (__u64)instance->memory;
    if (-1 == ioctl(instance->vm_fd, KVM_SET_USER_MEMORY_REGION, &region))
    {
        result = vm_result(VM_ERROR_INSTANCE, errno);
        goto exit;
    }
    instance->has_memory_region = 1;

    *pinstance = instance;
    result = VM_RESULT_SUCCESS;

exit:
    if (!vm_result_check(result) && 0 != instance)
        vm_delete(instance);

    return result;
}

vm_result_t vm_delete(vm_t *instance)
{
    if (instance->has_memory_region)
    {
        struct kvm_userspace_memory_region region;
        memset(&region, 0, sizeof region);
        ioctl(instance->vm_fd, KVM_SET_USER_MEMORY_REGION, &region);
    }

    if (MAP_FAILED != instance->memory)
        munmap(instance->memory, instance->config.memory_size);

    if (-1 != instance->vm_fd)
        close(instance->vm_fd);

    if (-1 != instance->hv_fd)
        close(instance->hv_fd);

    if (instance->has_barrier)
        pthread_barrier_destroy(&instance->barrier);

    if (instance->has_cancel_lock)
        pthread_mutex_destroy(&instance->cancel_lock);

    free(instance);

    return VM_RESULT_SUCCESS;
}

vm_result_t vm_set_debug_log(vm_t *instance, unsigned flags)
{
    instance->debug_log_flags = flags;

    return VM_RESULT_SUCCESS;
}

vm_result_t vm_start(vm_t *instance)
{
    vm_result_t result;
    int error;

    if (instance->has_thread)
    {
        result = VM_ERROR_MISUSE;
        goto exit;
    }

    atomic_store(&instance->thread_result, VM_RESULT_SUCCESS);

    pthread_mutex_lock(&instance->cancel_lock);

    if (!instance->is_cancelled)
    {
        instance->thread_count = instance->config.cpu_count;

        sigset_t newset, oldset;
        sigfillset(&newset);
        pthread_sigmask(SIG_SETMASK, &newset, &oldset);
        error = pthread_create(&instance->thread, 0, vm_thread, instance);
        pthread_sigmask(SIG_SETMASK, &oldset, 0);
            /* new thread has all signals blocked */

        if (0 != error)
            result = vm_result(VM_ERROR_THREAD, error);
        else
            instance->has_thread = 1;
    }
    else
    {
        error = EINTR; /* ignored */
        result = VM_ERROR_CANCELLED;
    }

    pthread_mutex_unlock(&instance->cancel_lock);

    if (0 != error)
        goto exit;

    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

vm_result_t vm_wait(vm_t *instance)
{
    vm_result_t result;
    void *retval;

    if (!instance->has_thread)
    {
        result = VM_ERROR_MISUSE;
        goto exit;
    }

    pthread_barrier_wait(&instance->barrier);

    pthread_mutex_lock(&instance->cancel_lock);

    pthread_join(instance->thread, &retval);
    instance->has_thread = 0;

    pthread_mutex_unlock(&instance->cancel_lock);

    result = atomic_load(&instance->thread_result);

exit:
    return result;
}

vm_result_t vm_cancel(vm_t *instance)
{
    pthread_mutex_lock(&instance->cancel_lock);

    instance->is_cancelled = 1;
    if (instance->has_thread)
        pthread_kill(instance->thread, SIGCANCEL);
            /* if target already dead this fails with ESRCH; that's ok, we want to kill it anyway */

    pthread_mutex_unlock(&instance->cancel_lock);

    return VM_RESULT_SUCCESS;
}

static __thread struct kvm_run *vm_thread_cpu_run;
static void *vm_thread(void *instance0)
{
    vm_result_t result;
    vm_t *instance = instance0;
    unsigned cpu_index;
    int cpu_fd = -1;
    struct kvm_run *cpu_run = MAP_FAILED;
    pthread_t next_thread;
    int is_first_thread, has_next_thread;
    struct sigaction action;
    sigset_t sigset;
    int error;

    /* thread has all signals blocked -- see vm_start */

    cpu_index = (unsigned)(instance->config.cpu_count - instance->thread_count);
    is_first_thread = instance->config.cpu_count == instance->thread_count;
    has_next_thread = 0;

    cpu_fd = ioctl(instance->vm_fd, KVM_CREATE_VCPU, (void *)(uintptr_t)cpu_index);
    if (-1 == cpu_fd)
    {
        result = vm_result(VM_ERROR_CPU, errno);
        goto exit;
    }

    cpu_run = mmap(
        0, (size_t)instance->cpu_run_size, PROT_READ | PROT_WRITE, MAP_SHARED, cpu_fd, 0);
    if (MAP_FAILED == cpu_run)
    {
        result = vm_result(VM_ERROR_CPU, errno);
        goto exit;
    }
    atomic_store_explicit(&vm_thread_cpu_run, cpu_run, memory_order_relaxed);

    /*
     * The following code block is thread-safe because the pthread_create call
     * ensures that we run in a lockstep fashion. This is because the call
     * must act as a barrier: by the time the new thread is created it must
     * observe the world as if all previous code has run.
     */
    if (1 < instance->thread_count)
    {
        instance->thread_count--;
        error = pthread_create(&next_thread, 0, vm_thread, instance);
        if (0 != error)
        {
            result = vm_result(VM_ERROR_THREAD, error);
            goto exit;
        }
        has_next_thread = 1;
    }

    memset(&action, 0, sizeof action);
    action.sa_handler = vm_thread_signal;
    sigaction(SIGCANCEL, &action, 0);

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGCANCEL);
    pthread_sigmask(SIG_UNBLOCK, &sigset, 0);

    for (;;)
    {
        if (-1 == ioctl(cpu_fd, KVM_RUN, NULL))
        {
            result = EINTR == errno ?
                VM_ERROR_CANCELLED :
                vm_result(VM_ERROR_CPU, errno);
            goto exit;
        }

        /*
         * In order to avoid a big switch statement we use a dispatch table.
         * So we squash the exit_reason into an index to the table.
         *
         * Is this really worth it? Don't know, but I did it anyway.
         * A sensible person would have done some perf measurements first.
         */
#define SQUASH(x)                       ((x) & 0x1f)
        static vm_result_t (*dispatch[32])(vm_t *instance, struct kvm_run *cpu_run) =
        {
            [0x00] = vm_cpuexit_unknown,
            [0x01] = vm_cpuexit_unknown,
            [0x02] = vm_cpuexit_unknown,
            [0x03] = vm_cpuexit_unknown,
            [0x04] = vm_cpuexit_unknown,
            [0x05] = vm_cpuexit_unknown,
            [0x06] = vm_cpuexit_unknown,
            [0x07] = vm_cpuexit_unknown,
            [0x08] = vm_cpuexit_unknown,
            [0x09] = vm_cpuexit_unknown,
            [0x0a] = vm_cpuexit_unknown,
            [0x0b] = vm_cpuexit_unknown,
            [0x0c] = vm_cpuexit_unknown,
            [0x0d] = vm_cpuexit_unknown,
            [0x0e] = vm_cpuexit_unknown,
            [0x0f] = vm_cpuexit_unknown,
            [0x10] = vm_cpuexit_unknown,
            [0x11] = vm_cpuexit_unknown,
            [0x12] = vm_cpuexit_unknown,
            [0x13] = vm_cpuexit_unknown,
            [0x14] = vm_cpuexit_unknown,
            [0x15] = vm_cpuexit_unknown,
            [0x16] = vm_cpuexit_unknown,
            [0x17] = vm_cpuexit_unknown,
            [0x18] = vm_cpuexit_unknown,
            [0x19] = vm_cpuexit_unknown,
            [0x1a] = vm_cpuexit_unknown,
            [0x1b] = vm_cpuexit_unknown,
            [0x1c] = vm_cpuexit_unknown,
            [0x1d] = vm_cpuexit_unknown,
            [0x1e] = vm_cpuexit_unknown,
            [0x1f] = vm_cpuexit_unknown,

            [SQUASH(KVM_EXIT_MMIO)] = vm_cpuexit_MMIO,
            [SQUASH(KVM_EXIT_IO)] = vm_cpuexit_IO,
        };
        int index = SQUASH(cpu_run->exit_reason);
#undef SQUASH

        result = dispatch[index](instance, cpu_run);
        if (instance->debug_log_flags)
            vm_debug_log(cpu_index, cpu_run, result);
        if (!vm_result_check(result))
            goto exit;
    }

exit:
    if (!vm_result_check(result))
    {
        vm_result_t expected = VM_RESULT_SUCCESS;
        atomic_compare_exchange_strong(&instance->thread_result, &expected, result);
    }

    if (has_next_thread)
    {
        void *retval;
        pthread_kill(next_thread, SIGCANCEL);
            /* if target already dead this fails with ESRCH; that's ok, we want to kill it anyway */
        pthread_join(next_thread, &retval);
    }

    if (MAP_FAILED != cpu_run)
    {
        atomic_store_explicit(&vm_thread_cpu_run, 0, memory_order_relaxed);
        munmap(cpu_run, (size_t)instance->cpu_run_size);
    }

    if (-1 != cpu_fd)
        close(cpu_fd);

    if (is_first_thread)
        pthread_barrier_wait(&instance->barrier);

    return 0;
}

static void vm_thread_signal(int signum)
{
    /*
     * Pthread_getspecific and __thread are not async-signal safe.
     * However in practice they are.
     *
     * See https://stackoverflow.com/a/24653340/568557
     * See https://sourceware.org/legacy-ml/libc-alpha/2012-06/msg00372.html
     */

    struct kvm_run *cpu_run = atomic_load_explicit(&vm_thread_cpu_run, memory_order_relaxed);
    if (0 != cpu_run)
        atomic_store_explicit(&cpu_run->immediate_exit, 1, memory_order_relaxed);
}

static vm_result_t vm_cpuexit_unknown(vm_t *instance, struct kvm_run *cpu_run)
{
    return VM_ERROR_CANCELLED;
}

static vm_result_t vm_cpuexit_MMIO(vm_t *instance, struct kvm_run *cpu_run)
{
    return VM_ERROR_CANCELLED;
}

static vm_result_t vm_cpuexit_IO(vm_t *instance, struct kvm_run *cpu_run)
{
    return VM_ERROR_CANCELLED;
}

static void vm_debug_log(unsigned cpu_index, struct kvm_run *cpu_run, vm_result_t result)
{
    char buffer[1024];
    char *exit_reason_str;
    ssize_t bytes;

    switch (cpu_run->exit_reason)
    {
    case KVM_EXIT_UNKNOWN:
        exit_reason_str = "UNKNOWN";
        break;
    case KVM_EXIT_EXCEPTION:
        exit_reason_str = "EXCEPTION";
        break;
    case KVM_EXIT_IO:
        exit_reason_str = "IO";
        break;
    case KVM_EXIT_HYPERCALL:
        exit_reason_str = "HYPERCALL";
        break;
    case KVM_EXIT_DEBUG:
        exit_reason_str = "DEBUG";
        break;
    case KVM_EXIT_HLT:
        exit_reason_str = "HLT";
        break;
    case KVM_EXIT_MMIO:
        exit_reason_str = "MMIO";
        break;
    case KVM_EXIT_IRQ_WINDOW_OPEN:
        exit_reason_str = "IRQ_WINDOW_OPEN";
        break;
    case KVM_EXIT_SHUTDOWN:
        exit_reason_str = "SHUTDOWN";
        break;
    case KVM_EXIT_FAIL_ENTRY:
        exit_reason_str = "FAIL_ENTRY";
        break;
    case KVM_EXIT_INTR:
        exit_reason_str = "INTR";
        break;
    case KVM_EXIT_SET_TPR:
        exit_reason_str = "SET_TPR";
        break;
    case KVM_EXIT_TPR_ACCESS:
        exit_reason_str = "TPR_ACCESS";
        break;
    case KVM_EXIT_S390_SIEIC:
        exit_reason_str = "S390_SIEIC";
        break;
    case KVM_EXIT_S390_RESET:
        exit_reason_str = "S390_RESET";
        break;
    case KVM_EXIT_DCR:
        exit_reason_str = "DCR";
        break;
    case KVM_EXIT_NMI:
        exit_reason_str = "NMI";
        break;
    case KVM_EXIT_INTERNAL_ERROR:
        exit_reason_str = "INTERNAL_ERROR";
        break;
    case KVM_EXIT_OSI:
        exit_reason_str = "OSI";
        break;
    case KVM_EXIT_PAPR_HCALL:
        exit_reason_str = "PAPR_HCALL";
        break;
    case KVM_EXIT_S390_UCONTROL:
        exit_reason_str = "S390_UCONTROL";
        break;
    case KVM_EXIT_WATCHDOG:
        exit_reason_str = "WATCHDOG";
        break;
    case KVM_EXIT_S390_TSCH:
        exit_reason_str = "S390_TSCH";
        break;
    case KVM_EXIT_EPR:
        exit_reason_str = "EPR";
        break;
    case KVM_EXIT_SYSTEM_EVENT:
        exit_reason_str = "SYSTEM_EVENT";
        break;
    case KVM_EXIT_S390_STSI:
        exit_reason_str = "S390_STSI";
        break;
    case KVM_EXIT_IOAPIC_EOI:
        exit_reason_str = "IOAPIC_EOI";
        break;
    case KVM_EXIT_HYPERV:
        exit_reason_str = "HYPERV";
        break;
    default:
        exit_reason_str = "?";
        break;
    }

    snprintf(buffer, sizeof buffer, "[%u] %s(cs:rip=%04x:%p, efl=%08x, pe=%d) = %d\n",
        cpu_index,
        exit_reason_str,
        cpu_run->s.regs.sregs.cs.selector, cpu_run->s.regs.regs.rip,
        (unsigned)cpu_run->s.regs.regs.rflags,
        (int)(cpu_run->s.regs.sregs.cr0 & 1),
        (int)(vm_result_error(result) >> 48));
    bytes = write(STDERR_FILENO, buffer, strlen(buffer));
    (void)bytes;
}
