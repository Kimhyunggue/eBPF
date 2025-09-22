#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define MAX_FILENAME_LEN 256
#define COMM_LEN 16

struct event_data{
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char exename[MAX_FILENAME_LEN];
    char filename[MAX_FILENAME_LEN];
    char comm[COMM_LEN];
}; //__attribute__((packed)) 

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} ringbuf_selfdel SEC(".maps");

SEC("lsm/path_unlink")
int BPF_PROG(path_unlink, const struct path *dir, struct dentry *dentry_arg)
{
    struct task_struct *task;
    struct event_data *eventdata;
    eventdata = bpf_ringbuf_reserve(&ringbuf_selfdel, sizeof(struct event_data), 0);
    if(!eventdata) {
        return 0; // No space in ring buffer
    }
    bpf_get_current_comm(&eventdata->comm, sizeof(eventdata->comm));
    task = bpf_get_current_task_btf();
    const unsigned char *name;

    bpf_probe_read_kernel(&eventdata->exename, sizeof(eventdata->exename),
                        &task->mm->exe_file->f_path.dentry->d_name.name);
    bpf_probe_read_kernel(&eventdata->filename, sizeof(eventdata->filename),
                        &dentry_arg->d_name.name);

    eventdata->pid = bpf_get_current_pid_tgid() >> 32;
    eventdata->ppid = task->real_parent->tgid;
    eventdata->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;


    bpf_printk("-------------------------------------------------- %s\n", " ");
    bpf_printk("Current file is being deleted value : %s\n", eventdata->filename);
    bpf_printk("Current excutable name : %s\n", eventdata->exename);
    bpf_printk("Current command using bpf_get_current_comm : %s\n", eventdata->comm);
    bpf_printk("Current PID : %d\n", eventdata->pid);
    bpf_printk("Current PPID : %d\n", eventdata->ppid);
    bpf_printk("Current UID : %d\n", eventdata->uid);
    bpf_printk("-------------------------------------------------- %s\n", " ");

    bpf_ringbuf_submit(eventdata, 0);

    return 0;
}

// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>

// char _license[] SEC("license") = "GPL";

// SEC("tracepoint/syscalls/sys_enter_unlinkat")
// int BPF_PROG(tracepoint_unlinkat)
// {
//     bpf_printk("unlinkat syscall entered!\n");
//     return 0;
// }