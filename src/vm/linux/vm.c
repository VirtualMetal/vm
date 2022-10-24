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
    int vcpu_run_size;
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
static vm_result_t vm_vcpu_init(vm_t *instance, int vcpu_fd);
static vm_result_t vm_vcpu_exit_unknown(vm_t *instance, struct kvm_run *vcpu_run);
static vm_result_t vm_vcpu_exit_mmio(vm_t *instance, struct kvm_run *vcpu_run);
static vm_result_t vm_vcpu_exit_io(vm_t *instance, struct kvm_run *vcpu_run);
static void vm_debug_log(unsigned vcpu_index, struct kvm_run *vcpu_run, vm_result_t result);

#define SIG_VCPU_CANCEL                 SIGUSR1

vm_result_t vm_create(const vm_config_t *config, vm_t **pinstance)
{
    vm_result_t result;
    vm_t *instance = 0;
    int error;

    *pinstance = 0;

    instance = malloc(sizeof *instance);
    if (0 == instance)
    {
        result = vm_result(VM_ERROR_MEMORY, 0);
        goto exit;
    }

    memset(instance, 0, sizeof *instance);
    instance->config = *config;
    instance->hv_fd = -1;
    instance->vm_fd = -1;
    instance->memory = MAP_FAILED;

    if (0 == instance->config.vcpu_count)
    {
        cpu_set_t affinity;
        CPU_ZERO(&affinity);
        if (-1 == sched_getaffinity(0, sizeof affinity, &affinity))
        {
            result = vm_result(VM_ERROR_HYPERVISOR, errno);
            goto exit;
        }
        instance->config.vcpu_count = (vm_count_t)CPU_COUNT(&affinity);
    }
    if (0 == instance->config.vcpu_count)
        instance->config.vcpu_count = 1;

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
        result = vm_result(VM_ERROR_HYPERVISOR, 0);
        goto exit;
    }

    if (0 >= ioctl(instance->hv_fd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY) ||
        0 >= ioctl(instance->hv_fd, KVM_CHECK_EXTENSION, KVM_CAP_IMMEDIATE_EXIT))
    {
        result = vm_result(VM_ERROR_HYPERVISOR, 0);
        goto exit;
    }

    instance->vcpu_run_size = ioctl(instance->hv_fd, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (-1 == instance->vcpu_run_size)
    {
        result = vm_result(VM_ERROR_HYPERVISOR, errno);
        goto exit;
    }

    instance->vm_fd = ioctl(instance->hv_fd, KVM_CREATE_VM, NULL);
    if (-1 == instance->vm_fd)
    {
        result = vm_result(VM_ERROR_HYPERVISOR, errno);
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
        result = vm_result(VM_ERROR_HYPERVISOR, errno);
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
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    atomic_store(&instance->thread_result, VM_RESULT_SUCCESS);

    pthread_mutex_lock(&instance->cancel_lock);

    if (!instance->is_cancelled)
    {
        instance->thread_count = instance->config.vcpu_count;

        sigset_t newset, oldset;
        sigfillset(&newset);
        pthread_sigmask(SIG_SETMASK, &newset, &oldset);
        error = pthread_create(&instance->thread, 0, vm_thread, instance);
        pthread_sigmask(SIG_SETMASK, &oldset, 0);
            /* new thread has all signals blocked */

        if (0 != error)
            result = vm_result(VM_ERROR_VCPU, error);
        else
            instance->has_thread = 1;
    }
    else
    {
        error = EINTR; /* ignored */
        result = vm_result(VM_ERROR_CANCELLED, 0);
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
        result = vm_result(VM_ERROR_MISUSE, 0);
        goto exit;
    }

    pthread_barrier_wait(&instance->barrier);

    pthread_mutex_lock(&instance->cancel_lock);

    pthread_join(instance->thread, &retval);
    instance->has_thread = 0;

    pthread_mutex_unlock(&instance->cancel_lock);

    result = atomic_load(&instance->thread_result);
    if (VM_ERROR_CANCELLED == vm_result_error(result))
        result = VM_RESULT_SUCCESS;

exit:
    return result;
}

vm_result_t vm_cancel(vm_t *instance)
{
    pthread_mutex_lock(&instance->cancel_lock);

    instance->is_cancelled = 1;
    if (instance->has_thread)
        pthread_kill(instance->thread, SIG_VCPU_CANCEL);
            /* if target already dead this fails with ESRCH; that's ok, we want to kill it anyway */

    pthread_mutex_unlock(&instance->cancel_lock);

    return VM_RESULT_SUCCESS;
}

static __thread struct kvm_run *vm_thread_vcpu_run;
static void *vm_thread(void *instance0)
{
    vm_result_t result;
    vm_t *instance = instance0;
    unsigned vcpu_index;
    int vcpu_fd = -1;
    struct kvm_run *vcpu_run = MAP_FAILED;
    pthread_t next_thread;
    int is_first_thread, has_next_thread;
    struct sigaction action;
    sigset_t sigset;
    int error;

    /* thread has all signals blocked -- see vm_start */

    vcpu_index = (unsigned)(instance->config.vcpu_count - instance->thread_count);
    is_first_thread = instance->config.vcpu_count == instance->thread_count;
    has_next_thread = 0;

    vcpu_fd = ioctl(instance->vm_fd, KVM_CREATE_VCPU, (void *)(uintptr_t)vcpu_index);
    if (-1 == vcpu_fd)
    {
        result = vm_result(VM_ERROR_VCPU, errno);
        goto exit;
    }

    vcpu_run = mmap(
        0, (size_t)instance->vcpu_run_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu_fd, 0);
    if (MAP_FAILED == vcpu_run)
    {
        result = vm_result(VM_ERROR_VCPU, errno);
        goto exit;
    }
    atomic_store_explicit(&vm_thread_vcpu_run, vcpu_run, memory_order_relaxed);

    result = vm_vcpu_init(instance, vcpu_fd);
    if (!vm_result_check(result))
        goto exit;

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
            result = vm_result(VM_ERROR_VCPU, error);
            goto exit;
        }
        has_next_thread = 1;
    }

    memset(&action, 0, sizeof action);
    action.sa_handler = vm_thread_signal;
    sigaction(SIG_VCPU_CANCEL, &action, 0);

    sigemptyset(&sigset);
    sigaddset(&sigset, SIG_VCPU_CANCEL);
    pthread_sigmask(SIG_UNBLOCK, &sigset, 0);

    for (;;)
    {
        if (-1 == ioctl(vcpu_fd, KVM_RUN, NULL))
        {
            result = EINTR == errno ?
                vm_result(VM_ERROR_CANCELLED, EINTR) :
                vm_result(VM_ERROR_VCPU, errno);
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
        static vm_result_t (*dispatch[32])(vm_t *instance, struct kvm_run *vcpu_run) =
        {
            [0x00] = vm_vcpu_exit_unknown,
            [0x01] = vm_vcpu_exit_unknown,
            [0x02] = vm_vcpu_exit_unknown,
            [0x03] = vm_vcpu_exit_unknown,
            [0x04] = vm_vcpu_exit_unknown,
            [0x05] = vm_vcpu_exit_unknown,
            [0x06] = vm_vcpu_exit_unknown,
            [0x07] = vm_vcpu_exit_unknown,
            [0x08] = vm_vcpu_exit_unknown,
            [0x09] = vm_vcpu_exit_unknown,
            [0x0a] = vm_vcpu_exit_unknown,
            [0x0b] = vm_vcpu_exit_unknown,
            [0x0c] = vm_vcpu_exit_unknown,
            [0x0d] = vm_vcpu_exit_unknown,
            [0x0e] = vm_vcpu_exit_unknown,
            [0x0f] = vm_vcpu_exit_unknown,
            [0x10] = vm_vcpu_exit_unknown,
            [0x11] = vm_vcpu_exit_unknown,
            [0x12] = vm_vcpu_exit_unknown,
            [0x13] = vm_vcpu_exit_unknown,
            [0x14] = vm_vcpu_exit_unknown,
            [0x15] = vm_vcpu_exit_unknown,
            [0x16] = vm_vcpu_exit_unknown,
            [0x17] = vm_vcpu_exit_unknown,
            [0x18] = vm_vcpu_exit_unknown,
            [0x19] = vm_vcpu_exit_unknown,
            [0x1a] = vm_vcpu_exit_unknown,
            [0x1b] = vm_vcpu_exit_unknown,
            [0x1c] = vm_vcpu_exit_unknown,
            [0x1d] = vm_vcpu_exit_unknown,
            [0x1e] = vm_vcpu_exit_unknown,
            [0x1f] = vm_vcpu_exit_unknown,

            [SQUASH(KVM_EXIT_MMIO)] = vm_vcpu_exit_mmio,
            [SQUASH(KVM_EXIT_IO)] = vm_vcpu_exit_io,
        };
        int index = SQUASH(vcpu_run->exit_reason);
#undef SQUASH

        result = dispatch[index](instance, vcpu_run);
        if (instance->debug_log_flags)
            vm_debug_log(vcpu_index, vcpu_run, result);
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
        pthread_kill(next_thread, SIG_VCPU_CANCEL);
            /* if target already dead this fails with ESRCH; that's ok, we want to kill it anyway */
        pthread_join(next_thread, &retval);
    }

    if (MAP_FAILED != vcpu_run)
    {
        atomic_store_explicit(&vm_thread_vcpu_run, 0, memory_order_relaxed);
        munmap(vcpu_run, (size_t)instance->vcpu_run_size);
    }

    if (-1 != vcpu_fd)
        close(vcpu_fd);

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

    struct kvm_run *vcpu_run = atomic_load_explicit(&vm_thread_vcpu_run, memory_order_relaxed);
    if (0 != vcpu_run)
        atomic_store_explicit(&vcpu_run->immediate_exit, 1, memory_order_relaxed);
}

static vm_result_t vm_vcpu_init(vm_t *instance, int vcpu_fd)
{
#if defined(__x86_64__)
    struct kvm_regs regs;
    struct kvm_sregs sregs;

    if (-1 == ioctl(vcpu_fd, (int)KVM_GET_SREGS, &sregs))
        return vm_result(VM_ERROR_VCPU, errno);

    sregs.cs.base = 0, sregs.cs.limit = 0xffff, sregs.cs.selector = 0;

    if (-1 == ioctl(vcpu_fd, KVM_SET_SREGS, &sregs))
        return vm_result(VM_ERROR_VCPU, errno);

    memset(&regs, 0, sizeof regs);
    regs.rflags = 2;
    if (-1 == ioctl(vcpu_fd, KVM_SET_REGS, &regs))
        return vm_result(VM_ERROR_VCPU, errno);

    return VM_RESULT_SUCCESS;
#endif
}

static vm_result_t vm_vcpu_exit_unknown(vm_t *instance, struct kvm_run *vcpu_run)
{
    return vm_result(VM_ERROR_CANCELLED, 0);
}

static vm_result_t vm_vcpu_exit_mmio(vm_t *instance, struct kvm_run *vcpu_run)
{
    return vm_result(VM_ERROR_CANCELLED, 0);
}

static vm_result_t vm_vcpu_exit_io(vm_t *instance, struct kvm_run *vcpu_run)
{
    return vm_result(VM_ERROR_CANCELLED, 0);
}

static void vm_debug_log(unsigned vcpu_index, struct kvm_run *vcpu_run, vm_result_t result)
{
    char buffer[1024];
    ssize_t bytes;

    switch (vcpu_run->exit_reason)
    {
    case KVM_EXIT_UNKNOWN:
        snprintf(buffer, sizeof buffer, "[%u] UNKNOWN(hardware_exit_reason=%llu) = %d\n",
            vcpu_index,
            (unsigned long long)vcpu_run->hw.hardware_exit_reason,
            (int)(vm_result_error(result) >> 48));
        break;
    case KVM_EXIT_HLT:
        snprintf(buffer, sizeof buffer, "[%u] HLT() = %d\n",
            vcpu_index,
            (int)(vm_result_error(result) >> 48));
        break;
    case KVM_EXIT_FAIL_ENTRY:
        snprintf(buffer, sizeof buffer, "[%u] FAIL_ENTRY(fail_entry=%llu) = %d\n",
            vcpu_index,
            (unsigned long long)vcpu_run->fail_entry.hardware_entry_failure_reason,
            (int)(vm_result_error(result) >> 48));
        break;
    case KVM_EXIT_INTERNAL_ERROR:
        snprintf(buffer, sizeof buffer, "[%u] INTERNAL_ERROR(suberror=%u) = %d\n",
            vcpu_index,
            (unsigned)vcpu_run->internal.suberror,
            (int)(vm_result_error(result) >> 48));
        break;
    default:
        snprintf(buffer, sizeof buffer, "[%u] EXIT=%x() = %d\n",
            vcpu_index,
            vcpu_run->exit_reason,
            (int)(vm_result_error(result) >> 48));
        break;
    }

    bytes = write(STDERR_FILENO, buffer, strlen(buffer));
    (void)bytes;
}
