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
    __u32 futex_op;    // futex 연산 종류 (WAIT, WAKE 등)
    __s64 retval;      // 반환값
    __u8 is_enter;     // 1: enter, 0: exit
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

// =================================================================
// 1. futex 진입 (Enter) 훅
// =================================================================
SEC("tracepoint/syscalls/sys_enter_futex")
int handle_futex_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    // futex(uaddr, futex_op, val, ...) 구조에서 args[1]이 futex_op 입니다.
    // 레지스터를 직접 읽을 필요 없이 tracepoint가 제공하는 args 배열을 사용합니다.
    e->futex_op = ctx->args[1]; 
    e->is_enter = 1;
    e->retval = 0;
    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =================================================================
// 2. futex 종료 (Exit) 훅
// =================================================================
SEC("tracepoint/syscalls/sys_exit_futex")
int handle_futex_exit(struct trace_event_raw_sys_exit *ctx) {
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->futex_op = 0;
    e->is_enter = 0;
    // sys_exit tracepoint는 반환값을 ret 필드로 깔끔하게 제공합니다.
    e->retval = ctx->ret; 
    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}