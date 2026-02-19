
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h> // BPF_CORE_READ 매크로 사용을 위해 추가

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} my_pid_map SEC(".maps");

// 1. 이벤트 구조체 수정 (enter/exit 구분 및 리턴값 추가)
struct event {
    __u32 pid;
    __u64 syscall_id;
    __s64 retval;      // sys_exit에서 반환값 저장용
    __u8 is_enter;     // 1: enter, 0: exit
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");


// =================================================================
// 1. sys_enter 훅 (기존 코드 수정)
// =================================================================
SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx){
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if(pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if(my_pid && *my_pid == pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e) return 0;

    e->is_enter = 1;                     // 들어가는 중(enter)임을 표시
    e->syscall_id = ctx->args[1];        // sys_enter의 args[1]은 syscall_id
    e->retval = 0;                       // 아직 실행 전이므로 리턴값 없음
    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}


// =================================================================
// 2. sys_exit 훅 (새로 추가)
// =================================================================
SEC("raw_tracepoint/sys_exit")
int handle_sys_exit(struct bpf_raw_tracepoint_args *ctx){
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if(pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if(my_pid && *my_pid == pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e) return 0;

    e->is_enter = 0;                     // 나오는 중(exit)임을 표시
    
    // sys_exit의 args[0]은 pt_regs 포인터, args[1]은 리턴값입니다.
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    
    // x86_64 아키텍처 기준: orig_ax 레지스터에 원본 syscall_id가 보존되어 있습니다.
    e->syscall_id = BPF_CORE_READ(regs, orig_ax); 
    
    e->retval = ctx->args[1];            // sys_exit의 args[1]은 실행 결과 반환값
    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}