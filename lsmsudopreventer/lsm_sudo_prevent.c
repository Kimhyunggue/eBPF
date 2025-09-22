#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
// #include <linux/errno.h>

char LICENCE[] SEC("license") = "GPL";

#define MAX_FILENAME_LEN 21

struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_FILENAME_LEN]);
    __type(value, sizeof(u32));
} not_allowed_bins SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm) {
    u32 cred_uid = -1;
    u32 cred_eid = -1;

    char fname[MAX_FILENAME_LEN] = {0};

    bpf_probe_read_kernel_str(fname, sizeof(fname), bprm->filename);
    bpf_probe_read_kernel(&cred_uid, sizeof(cred_uid), &bprm->cred->uid.val);
    bpf_probe_read_kernel(&cred_eid, sizeof(cred_eid), &bprm->cred->euid.val);
    u32 userid = -1;
    bpf_probe_read_kernel(&userid, sizeof(userid), &bprm->cred->user->uid.val);

    struct task_struct *task = bpf_get_current_task_btf();
    char parent_comm[16];
    bpf_probe_read_kernel(&parent_comm, sizeof(parent_comm), &task->real_parent->comm);

    u32 parent_uid = -1;
    bpf_probe_read_kernel(&parent_uid, sizeof(parent_uid), &task->real_parent->cred->uid.val);

    bpf_printk("Parent commnad is %s with UID %d\n", parent_comm, parent_uid);
    bpf_printk("Filename using read_kernel : %s with UID %d and EID %d and User ID %d\n", 
               fname, cred_uid, cred_eid, userid);

    if(parent_uid == 0){
        return 0;
    }

    int* not_allowed = bpf_map_lookup_elem(&not_allowed_bins, &fname);
    if(not_allowed) {
        if(cred_uid == 0){
            bpf_printk("sudo attemp for %s\n",fname);
            return -1;
        }
    }

    return 0;
}