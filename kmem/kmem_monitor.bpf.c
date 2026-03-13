#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} my_pid_map SEC(".maps");

// 💡 유저 스페이스로 넘길 데이터 (심플하게 유지)
struct event {
    __u32 pid;
    __u32 event_type; // 내가 복붙하면서 직접 지정할 번호 (1번, 2번...)
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");


// =================================================================
// 1. 첫 번째 훅 (이 블록을 그대로 복사해서 이름과 번호만 바꾸시면 됩니다)
// =================================================================
SEC("tracepoint/kmem/kmalloc")
int handle_kmalloc(void *ctx) {
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->event_type = 1; 
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =================================================================
// 2. 두 번째 훅 (복사 + 붙여넣기 한 예시)
// =================================================================
SEC("tracepoint/kmem/kfree")
int handle_kfree(void *ctx) {
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->event_type = 2; 
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =================================================================
// 3. 세 번째 훅
// =================================================================
SEC("tracepoint/kmem/kmem_cache_alloc")
int handle_kmem_cache_alloc(void *ctx) {
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->event_type = 3; 
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =================================================================
// 4. 네 번째 훅
// =================================================================
SEC("tracepoint/kmem/kmem_cache_free")
int handle_kmem_cache_free(void *ctx) {
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->event_type = 4; 
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =================================================================
// 5. 다섯 번째 훅
// =================================================================
SEC("tracepoint/kmem/mm_alloc_contig_migrate_range_info")
int handle_kmem_mm_alloc_contig_migrate_range_info(void *ctx) {
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->event_type = 5; 
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =================================================================
// 6. 여섯 번째 훅
// =================================================================
SEC("tracepoint/kmem/mm_page_alloc")
int handle_kmem_mm_page_alloc(void *ctx) {
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->event_type = 6; 
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =================================================================
// 7. 일곱 번째 훅
// =================================================================
SEC("tracepoint/kmem/mm_page_alloc_extfrag")
int handle_kmem_mm_page_alloc_extfrag(void *ctx) {
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->event_type = 7; 
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =================================================================
// 8. 여덟 번째 훅
// =================================================================
SEC("tracepoint/kmem/mm_page_alloc_zone_locked")
int handle_kmem_mm_page_alloc_zone_locked(void *ctx) {
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->event_type = 8; 
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =================================================================
// 9. 아홉 번째 훅
// =================================================================
SEC("tracepoint/kmem/mm_page_free")
int handle_kmem_mm_page_free(void *ctx) {
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->event_type = 9; 
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =================================================================
// 10. 열 번째 훅
// =================================================================
SEC("tracepoint/kmem/mm_page_free_batched")
int handle_kmem_mm_page_free_batched(void *ctx) {
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->event_type = 10; 
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =================================================================
// 11. 열한 번째 훅
// =================================================================
SEC("tracepoint/kmem/mm_page_pcpu_drain")
int handle_kmem_mm_page_pcpu_drain(void *ctx) {
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->event_type = 11; 
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =================================================================
// 12. 열두 번째 훅
// =================================================================
SEC("tracepoint/kmem/rss_stat")
int handle_kmem_rss_stat(void *ctx) {
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == 0) return 0;

    __u32 *my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if (my_pid && *my_pid == pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->event_type = 12; 
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}