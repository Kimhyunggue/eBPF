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
    __u32 event_type; // 1~30번까지 훅 종류 구분
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB (이벤트 폭주로 금방 꽉 찰 겁니다)
} events SEC(".maps");

// =================================================================
// 💡 일반 스케줄러(sched) 훅 전용 매크로
// =================================================================
#define DEFINE_SCHED_HOOK(hook_name, type_id) \
SEC("tracepoint/sched/" #hook_name) \
int handle_##hook_name(void *ctx) { \
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
// 💡 확장 스케줄러(sched_ext) 훅 전용 매크로
// =================================================================
#define DEFINE_SCHED_EXT_HOOK(hook_name, type_id) \
SEC("tracepoint/sched_ext/" #hook_name) \
int handle_ext_##hook_name(void *ctx) { \
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
// 30개의 트레이스포인트 일괄 부착
// =================================================================
DEFINE_SCHED_HOOK(sched_kthread_stop, 1)
DEFINE_SCHED_HOOK(sched_kthread_stop_ret, 2)
DEFINE_SCHED_HOOK(sched_kthread_work_execute_end, 3)
DEFINE_SCHED_HOOK(sched_kthread_work_execute_start, 4)
DEFINE_SCHED_HOOK(sched_kthread_work_queue_work, 5)
DEFINE_SCHED_HOOK(sched_migrate_task, 6)
DEFINE_SCHED_HOOK(sched_move_numa, 7)
DEFINE_SCHED_HOOK(sched_pi_setprio, 8)
DEFINE_SCHED_HOOK(sched_prepare_exec, 9)
DEFINE_SCHED_HOOK(sched_process_exec, 10)
DEFINE_SCHED_HOOK(sched_process_exit, 11)
DEFINE_SCHED_HOOK(sched_process_fork, 12)
DEFINE_SCHED_HOOK(sched_process_free, 13)
DEFINE_SCHED_HOOK(sched_process_hang, 14)
DEFINE_SCHED_HOOK(sched_process_wait, 15)
DEFINE_SCHED_HOOK(sched_skip_vma_numa, 16)
DEFINE_SCHED_HOOK(sched_stat_blocked, 17)
DEFINE_SCHED_HOOK(sched_stat_iowait, 18)
DEFINE_SCHED_HOOK(sched_stat_runtime, 19)
DEFINE_SCHED_HOOK(sched_stat_sleep, 20)
DEFINE_SCHED_HOOK(sched_stat_wait, 21)
DEFINE_SCHED_HOOK(sched_stick_numa, 22)
DEFINE_SCHED_HOOK(sched_swap_numa, 23)
DEFINE_SCHED_HOOK(sched_switch, 24)
DEFINE_SCHED_HOOK(sched_wait_task, 25)
DEFINE_SCHED_HOOK(sched_wake_idle_without_ipi, 26)
DEFINE_SCHED_HOOK(sched_wakeup, 27)
DEFINE_SCHED_HOOK(sched_wakeup_new, 28)
DEFINE_SCHED_HOOK(sched_waking, 29)

// sched_ext 카테고리
DEFINE_SCHED_EXT_HOOK(sched_ext_dump, 30)