#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} my_pid_map SEC(".maps");

// 코어별 전용 고속 카운터(PERCPU)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} kmem_counter SEC(".maps");

// =================================================================
// 💡 Kmem 훅 전용 매크로
// =================================================================
#define DEFINE_KMEM_HOOK(hook_name) \
SEC("tracepoint/kmem/" #hook_name) \
int handle_##hook_name(void *ctx) { \
    __u32 zero = 0; \
    __u32 pid = bpf_get_current_pid_tgid() >> 32; \
    if (pid == 0) return 0; \
    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero); \
    if (my_pid && *my_pid == pid) return 0; \
    __u64 *val = bpf_map_lookup_elem(&kmem_counter, &zero); \
    if (val) { *val += 1; } \
    return 0; \
}

// 12개의 kmem 트레이스포인트 일괄 부착 (Syscall 제거됨)
DEFINE_KMEM_HOOK(kmalloc)
DEFINE_KMEM_HOOK(kfree)
DEFINE_KMEM_HOOK(kmem_cache_alloc)
DEFINE_KMEM_HOOK(kmem_cache_free)
DEFINE_KMEM_HOOK(mm_alloc_contig_migrate_range_info)
DEFINE_KMEM_HOOK(mm_page_alloc)
DEFINE_KMEM_HOOK(mm_page_alloc_extfrag)
DEFINE_KMEM_HOOK(mm_page_alloc_zone_locked)
DEFINE_KMEM_HOOK(mm_page_free)
DEFINE_KMEM_HOOK(mm_page_free_batched)
DEFINE_KMEM_HOOK(mm_page_pcpu_drain)
DEFINE_KMEM_HOOK(rss_stat)