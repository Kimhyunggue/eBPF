#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <stdatomic.h>
#include <bpf/libbpf.h>
#include "all_in_one.skel.h" 

struct event {
    __u32 pid;
    __u32 event_type;
    char comm[16];
};

#define EVENT_BUFFER_SIZE 524288 // 버퍼 사이즈를 2배로 넉넉하게!
struct event event_buffer[EVENT_BUFFER_SIZE];
static atomic_long event_count = 0;
static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) { return 0; }

int handle_event(void *ctx, void *data, size_t data_sz){
    if(data_sz != sizeof(struct event)) return 0; 
    
    long index = atomic_fetch_add(&event_count, 1);
    if(index < EVENT_BUFFER_SIZE){
        memcpy(&event_buffer[index], data, sizeof(struct event));
    }
    return 0;
}

void cleanup(struct ring_buffer *rb, struct all_in_one_bpf *skel){
    if (rb) ring_buffer__free(rb);
    if (skel) all_in_one_bpf__destroy(skel);
}

int main(int argc, char **argv){
    struct all_in_one_bpf *skel; 
    struct ring_buffer *rb = NULL;

    libbpf_set_print(libbpf_print_fn);

    skel = all_in_one_bpf__open_and_load();
    if (!skel) return 1;

    if (all_in_one_bpf__attach(skel)) {
        cleanup(rb, skel);
        return 1;
    }
    
    __u32 zero = 0, my_pid = getpid();
    bpf_map__update_elem(skel->maps.my_pid_map, &zero, sizeof(zero), &my_pid, sizeof(my_pid), BPF_ANY);

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if(!rb) { cleanup(rb, skel); return 1; }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("🔥 46개의 모든 훅(futex + kmem + sched + sys_enter/exit) 부착 완료!\n");
    printf("Events will flood the ring buffer. Measuring counts...\n");
    printf("Press Ctrl+C to exit...\n");
    
    time_t last_print_time = time(NULL);

    while(!exiting){
        ring_buffer__poll(rb, 1000); 

        time_t now = time(NULL);
        if(now - last_print_time >= 1){ 
            long count = atomic_exchange(&event_count, 0);
            
            if(count > 0){
                printf("Collected %ld ALL-IN-ONE events in last 1s\n", count);
            }
            last_print_time = now;
        }
    }

    cleanup(rb, skel);
    return 0;
}