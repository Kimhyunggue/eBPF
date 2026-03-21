#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// 자기 자신(tracer) PID 필터링용 맵
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} my_pid_map SEC(".maps");

// 💡 링버퍼를 지우고, 커널 내부 고속 카운터 맵을 추가!
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sched_counter SEC(".maps");

// =================================================================
// 💡 일반 스케줄러(sched) 훅 전용 매크로 (카운팅용으로 최적화)
// =================================================================
#define DEFINE_SCHED_HOOK(hook_name) \
SEC("tracepoint/sched/" #hook_name) \
int handle_##hook_name(void *ctx) { \
    __u32 zero = 0; \
    __u32 pid = bpf_get_current_pid_tgid() >> 32; \
    if (pid == 0) return 0; \
    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero); \
    if (my_pid && *my_pid == pid) return 0; \
    __u64 *val = bpf_map_lookup_elem(&sched_counter, &zero); \
    if (val) { __sync_fetch_and_add(val, 1); } \
    return 0; \
}

// =================================================================
// 29개의 트레이스포인트 일괄 부착
// =================================================================
DEFINE_SCHED_HOOK(sched_kthread_stop)
DEFINE_SCHED_HOOK(sched_kthread_stop_ret)
DEFINE_SCHED_HOOK(sched_kthread_work_execute_end)
DEFINE_SCHED_HOOK(sched_kthread_work_execute_start)
DEFINE_SCHED_HOOK(sched_kthread_work_queue_work)
DEFINE_SCHED_HOOK(sched_migrate_task)
DEFINE_SCHED_HOOK(sched_move_numa)
DEFINE_SCHED_HOOK(sched_pi_setprio)
DEFINE_SCHED_HOOK(sched_prepare_exec)
DEFINE_SCHED_HOOK(sched_process_exec)
DEFINE_SCHED_HOOK(sched_process_exit)
DEFINE_SCHED_HOOK(sched_process_fork)
DEFINE_SCHED_HOOK(sched_process_free)
DEFINE_SCHED_HOOK(sched_process_hang)
DEFINE_SCHED_HOOK(sched_process_wait)
DEFINE_SCHED_HOOK(sched_skip_vma_numa)
DEFINE_SCHED_HOOK(sched_stat_blocked)
DEFINE_SCHED_HOOK(sched_stat_iowait)
DEFINE_SCHED_HOOK(sched_stat_runtime)
DEFINE_SCHED_HOOK(sched_stat_sleep)
DEFINE_SCHED_HOOK(sched_stat_wait)
DEFINE_SCHED_HOOK(sched_stick_numa)
DEFINE_SCHED_HOOK(sched_swap_numa)
DEFINE_SCHED_HOOK(sched_switch)
DEFINE_SCHED_HOOK(sched_wait_task)
DEFINE_SCHED_HOOK(sched_wake_idle_without_ipi)
DEFINE_SCHED_HOOK(sched_wakeup)
DEFINE_SCHED_HOOK(sched_wakeup_new)
DEFINE_SCHED_HOOK(sched_waking)
