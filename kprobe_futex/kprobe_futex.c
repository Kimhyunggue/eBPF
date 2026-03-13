#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <stdatomic.h>
#include <bpf/libbpf.h>
// 1. 스켈레톤 헤더 변경 (kprobe 버전)
#include "kprobe_futex.skel.h" 

struct event {
    __u32 pid;
    __u32 futex_op;    
    __s64 retval;      
    __u8 is_enter;     
    char comm[16];
};

#define EVENT_BUFFER_SIZE 262144 
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

void cleanup(struct ring_buffer *rb, struct kprobe_futex_bpf *skel){
    if (rb) ring_buffer__free(rb);
    if (skel) kprobe_futex_bpf__destroy(skel);
}

int main(int argc, char **argv){
    struct kprobe_futex_bpf *skel; 
    struct ring_buffer *rb = NULL;

    libbpf_set_print(libbpf_print_fn);

    skel = kprobe_futex_bpf__open_and_load();
    if (!skel) return 1;

    if (kprobe_futex_bpf__attach(skel)) {
        cleanup(rb, skel);
        return 1;
    }
    
    __u32 zero = 0, my_pid = getpid();
    bpf_map__update_elem(skel->maps.my_pid_map, &zero, sizeof(zero), &my_pid, sizeof(my_pid), BPF_ANY);

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if(!rb) { cleanup(rb, skel); return 1; }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Attached Kprobe to do_futex! Measuring overhead...\n");
    printf("Events are being pulled but not printed. Press Ctrl+C to exit...\n");
    
    time_t last_print_time = time(NULL);

    while(!exiting){
        // 커널에서 데이터를 퍼옵니다.
        ring_buffer__poll(rb, 1000); 

        time_t now = time(NULL);
        if(now - last_print_time >= 1){ 
            long count = atomic_exchange(&event_count, 0);
            
            // 데이터가 오고 있는지 확인용으로 카운트만 찍습니다 (I/O 부하 거의 없음)
            if(count > 0){
                printf("Collected %ld kprobe events in last 1s\n", count);
            }
            last_print_time = now;
        }
    }

    cleanup(rb, skel);
    return 0;
}