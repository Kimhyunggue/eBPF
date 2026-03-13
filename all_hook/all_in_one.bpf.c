#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} my_pid_map SEC(".maps");

struct event {
    __u32 pid;
    __u32 event_type; // 어떤 훅에서 왔는지 구분하기 위한 ID
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB (이벤트 폭주 대비)
} events SEC(".maps");

// =================================================================
// 💡 공통 훅 생성 매크로 (중복 코드 제거)
// =================================================================
#define DEFINE_HOOK(category, hook_name, type_id) \
SEC("tracepoint/" #category "/" #hook_name) \
int handle_##category_##hook_name(void *ctx) { \
    __u32 zero = 0; \
    __u32 pid = bpf_get_current_pid_tgid() >> 32; \
    if (pid == 0) return 0; \
    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero); \
    if (my_pid && *my_pid == pid) return 0; \
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); \
    if (!e) return 0; \
    e->pid = pid; \
    e->event_type = type_id; \
    bpf_get_current_comm(&e->comm, sizeof(e->comm)); \
    bpf_ringbuf_submit(e, 0); \
    return 0; \
}

// =================================================================
// 1. FUTEX 훅 (Syscalls 카테고리)
// =================================================================
DEFINE_HOOK(syscalls, sys_enter_futex, 1)
DEFINE_HOOK(syscalls, sys_exit_futex, 2)

// =================================================================
// 2. KMEM 훅 (12개)
// =================================================================
DEFINE_HOOK(kmem, kfree, 10)
DEFINE_HOOK(kmem, kmalloc, 11)
DEFINE_HOOK(kmem, kmem_cache_alloc, 12)
DEFINE_HOOK(kmem, kmem_cache_free, 13)
DEFINE_HOOK(kmem, mm_alloc_contig_migrate_range_info, 14)
DEFINE_HOOK(kmem, mm_page_alloc, 15)
DEFINE_HOOK(kmem, mm_page_alloc_extfrag, 16)
DEFINE_HOOK(kmem, mm_page_alloc_zone_locked, 17)
DEFINE_HOOK(kmem, mm_page_free, 18)
DEFINE_HOOK(kmem, mm_page_free_batched, 19)
DEFINE_HOOK(kmem, mm_page_pcpu_drain, 20)
DEFINE_HOOK(kmem, rss_stat, 21)

// =================================================================
// 3. SCHED 훅 (29개 + sched_ext 1개)
// =================================================================
DEFINE_HOOK(sched, sched_kthread_stop, 30)
DEFINE_HOOK(sched, sched_kthread_stop_ret, 31)
DEFINE_HOOK(sched, sched_kthread_work_execute_end, 32)
DEFINE_HOOK(sched, sched_kthread_work_execute_start, 33)
DEFINE_HOOK(sched, sched_kthread_work_queue_work, 34)
DEFINE_HOOK(sched, sched_migrate_task, 35)
DEFINE_HOOK(sched, sched_move_numa, 36)
DEFINE_HOOK(sched, sched_pi_setprio, 37)
DEFINE_HOOK(sched, sched_prepare_exec, 38)
DEFINE_HOOK(sched, sched_process_exec, 39)
DEFINE_HOOK(sched, sched_process_exit, 40)
DEFINE_HOOK(sched, sched_process_fork, 41)
DEFINE_HOOK(sched, sched_process_free, 42)
DEFINE_HOOK(sched, sched_process_hang, 43)
DEFINE_HOOK(sched, sched_process_wait, 44)
DEFINE_HOOK(sched, sched_skip_vma_numa, 45)
DEFINE_HOOK(sched, sched_stat_blocked, 46)
DEFINE_HOOK(sched, sched_stat_iowait, 47)
DEFINE_HOOK(sched, sched_stat_runtime, 48)
DEFINE_HOOK(sched, sched_stat_sleep, 49)
DEFINE_HOOK(sched, sched_stat_wait, 50)
DEFINE_HOOK(sched, sched_stick_numa, 51)
DEFINE_HOOK(sched, sched_swap_numa, 52)
DEFINE_HOOK(sched, sched_switch, 53)
DEFINE_HOOK(sched, sched_wait_task, 54)
DEFINE_HOOK(sched, sched_wake_idle_without_ipi, 55)
DEFINE_HOOK(sched, sched_wakeup, 56)
DEFINE_HOOK(sched, sched_wakeup_new, 57)
DEFINE_HOOK(sched, sched_waking, 58)
DEFINE_HOOK(sched_ext, sched_ext_dump, 59)

// =================================================================
// 4. 모든 시스템 콜 진입/종료 (Raw Tracepoint)
// =================================================================
SEC("raw_tracepoint/sys_enter")
int handle_raw_sys_enter(void *ctx) {
    __u32 zero = 0, pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0) return 0;
    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid; e->event_type = 100;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int handle_raw_sys_exit(void *ctx) {
    __u32 zero = 0, pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0) return 0;
    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid; e->event_type = 101;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}