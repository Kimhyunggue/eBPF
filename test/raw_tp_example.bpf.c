#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} my_pid_map SEC(".maps");


struct event{
    __u32 pid;
    __u64 syscall_id;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx){
    __u32 zero = 0;
    __u32 *my_pid;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;     // 상위 32비트가 PID임 -> 현재 프로세스 PID 가져오기 

    if(pid == 0){ // PID 0은 커널 스케쥴러이므로 무시
        return 0;
    }
    
    my_pid = bpf_map_lookup_elem(&my_pid_map, &zero); // 로더 자신의 PID 가져오기

    if(my_pid && *my_pid == pid){
        return 0;
    }

    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){
        return 0;
    }

    e->syscall_id = ctx->args[1];
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);

    // char comm[16];
    // bpf_get_current_comm(&comm, sizeof(comm));

    // unsigned long syscall_id = ctx->args[1];

    // bpf_printk("Process '%s' called syscall ID %lu", comm, syscall_id);
    
    return 0;
}