#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

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