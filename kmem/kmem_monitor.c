#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <stdatomic.h>
#include <bpf/libbpf.h>
#include "kmem_monitor.skel.h" // 👈 파일명에 맞춘 스켈레톤 헤더

// 💡 커널에서 정의한 구조체와 완벽하게 동일해야 합니다.
struct event {
    __u32 pid;
    __u32 event_type;
    char comm[16];
};

#define EVENT_BUFFER_SIZE 262144 // 약 26만 개 (이벤트 폭주를 대비해 넉넉히)
struct event event_buffer[EVENT_BUFFER_SIZE];
static atomic_long event_count = 0;
static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) { return 0; }

int handle_event(void *ctx, void *data, size_t data_sz){
    if(data_sz != sizeof(struct event)) return 0; 
    
    long index = atomic_fetch_add(&event_count, 1);
    if(index < EVENT_BUFFER_SIZE){
        // 데이터를 배열에 복사만 해둡니다 (파일 출력 X)
        memcpy(&event_buffer[index], data, sizeof(struct event));
    }
    return 0;
}

void cleanup(struct ring_buffer *rb, struct kmem_monitor_bpf *skel){
    if (rb) ring_buffer__free(rb);
    if (skel) kmem_monitor_bpf__destroy(skel);
}

int main(int argc, char **argv){
    struct kmem_monitor_bpf *skel; 
    struct ring_buffer *rb = NULL;

    libbpf_set_print(libbpf_print_fn);

    // 1. 커널 코드 로드
    skel = kmem_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 2. 12개의 Tracepoint 훅 한 번에 부착!
    if (kmem_monitor_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        cleanup(rb, skel);
        return 1;
    }
    
    // 3. 내 로더 프로세스는 감시 대상에서 제외 (무한 루프 방지)
    __u32 zero = 0, my_pid = getpid();
    bpf_map__update_elem(skel->maps.my_pid_map, &zero, sizeof(zero), &my_pid, sizeof(my_pid), BPF_ANY);

    // 4. 링버퍼 생성
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if(!rb) { 
        fprintf(stderr, "Failed to create ring buffer\n");
        cleanup(rb, skel); 
        return 1; 
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Successfully attached to 12 kmem tracepoints!\n");
    printf("Measuring overhead... (No file I/O, just polling and counting)\n");
    printf("Press Ctrl+C to exit...\n");
    
    time_t last_print_time = time(NULL);

    while(!exiting){
        // 1초 단위 타임아웃으로 버퍼 폴링
        ring_buffer__poll(rb, 1000); 

        time_t now = time(NULL);
        if(now - last_print_time >= 1){ 
            long count = atomic_exchange(&event_count, 0);
            
            if(count > 0){
                printf("Collected %ld kmem events in last 1s\n", count);
            }
            last_print_time = now;
        }
    }

    printf("\nDetaching and cleaning up...\n");
    cleanup(rb, skel);
    return 0;
}