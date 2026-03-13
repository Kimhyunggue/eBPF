#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h> // kprobe 매크로 사용을 위해 필수

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} my_pid_map SEC(".maps");

struct event {
    __u32 pid;
    __u32 futex_op;
    __s64 retval;
    __u8 is_enter;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

// =================================================================
// 1. kprobe 훅: do_futex 함수가 시작될 때 트리거
// =================================================================
SEC("kprobe/do_futex")
int BPF_KPROBE(handle_do_futex, u32 *uaddr, int op, u32 val) {
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;

    // 💡 (선택) 만약 데이터를 넘기는 오버헤드조차 빼고 싶다면 여기서부터 주석 처리하세요.
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->futex_op = op; // BPF_KPROBE 덕분에 2번째 인자인 op를 바로 가져올 수 있습니다.
    e->is_enter = 1;
    e->retval = 0;
    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);

    return 0;
}

// =================================================================
// 2. kretprobe 훅: do_futex 함수가 종료되고 값을 반환할 때 트리거
// =================================================================
SEC("kretprobe/do_futex")
int BPF_KRETPROBE(handle_do_futex_exit, long ret) {
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->futex_op = 0;
    e->is_enter = 0;
    e->retval = ret; // BPF_KRETPROBE 덕분에 반환값 ret을 바로 가져옵니다.
    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);

    return 0;
}