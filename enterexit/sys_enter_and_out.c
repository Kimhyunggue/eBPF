#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <stdatomic.h>
#include <bpf/libbpf.h>
#include "sys_enter_and_out.skel.h" // [수정됨] 스켈레톤 헤더 이름 변경

// 1. 커널의 event 구조체와 완벽히 일치해야 합니다. (순서 및 크기 주의)
struct event {
    __u32 pid;
    __u64 syscall_id;
    __s64 retval;      // sys_exit 반환값
    __u8 is_enter;     // 1=enter, 0=exit
    char comm[16];
};

#define EVENT_BUFFER_SIZE 262144 // 2^18, 약 8MB
struct event event_buffer[EVENT_BUFFER_SIZE];
static atomic_long event_count = 0;

static volatile bool exiting = false;

// 함수 선언부
static void sig_handler(int sig);
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args);
// [수정됨] 스켈레톤 구조체 이름 변경
void cleanup(struct ring_buffer *rb, struct sys_enter_and_out_bpf *skel);
int handle_event(void *ctx, void *data, size_t data_sz);

int main(int argc, char **argv){
    struct sys_enter_and_out_bpf *skel; // [수정됨]
    struct ring_buffer *rb = NULL;
    int err;
    time_t last_print_time;
    FILE *log_file = NULL;

    libbpf_set_print(libbpf_print_fn);

    // 1. BPF 프로그램 Open & Load [수정됨]
    skel = sys_enter_and_out_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 2. 훅 Attach (sys_enter, sys_exit 모두 걸림) [수정됨]
    err = sys_enter_and_out_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        cleanup(rb, skel);
        return -err;
    }
    
    // 3. 내 프로세스 PID를 커널 맵에 전달하여 모니터링 제외
    __u32 zero = 0;
    __u32 my_pid = getpid();
    err = bpf_map__update_elem(skel->maps.my_pid_map, &zero, sizeof(zero), &my_pid, sizeof(my_pid), BPF_ANY);
    if(err < 0){
        fprintf(stderr, "Failed to update my_pid_map : %d, %s\n", err, strerror(-err));
        cleanup(rb, skel);
        return -err;
    }

    // 4. Ring Buffer 설정
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if(!rb){
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        cleanup(rb, skel);
        return -err;
    }

    // 5. 시그널 핸들러 등록
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 6. 로그 파일 열기
    log_file = fopen("sys_enter_and_out.log", "a");
    if(!log_file){
        fprintf(stderr, "Failed to open log file : %s\n", strerror(errno));
        cleanup(rb, skel);
        return 1;
    }

    printf("Successfully Started! Monitoring sys_enter & sys_exit...\n");
    printf("Press Ctrl+C to exit.\n");
    last_print_time = time(NULL);

    // 7. 메인 루프 (Polling & Logging)
    while(!exiting){
        err = ring_buffer__poll(rb, 1000); // 1초 타임아웃

        if(err < 0 && err != -EINTR){
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }

        time_t now = time(NULL);
        if(now - last_print_time >= 1){ // 1초에 한 번씩 버퍼 비우기
            long count = atomic_exchange(&event_count, 0);

            if(count > 0){
                fprintf(log_file, "Logging Events in Last period (~1s) : %ld\n", count);

                long print_limit = (count < 10) ? count : 10;
                
                for (long i = 0; i < print_limit; i++) {
                    struct event *evt = &event_buffer[i];
                    if(evt->pid == 0) continue; 

                    const char* type_str = evt->is_enter ? "ENTER" : "EXIT ";
                    
                    if (evt->is_enter) {
                        fprintf(log_file, "{\"TYPE\": \"%s\", \"PID\": %u, \"COMM\": \"%s\", \"SYSCALL_ID\": %llu}\n",
                            type_str, evt->pid, evt->comm, evt->syscall_id);
                    } else {
                        fprintf(log_file, "{\"TYPE\": \"%s\", \"PID\": %u, \"COMM\": \"%s\", \"SYSCALL_ID\": %llu, \"RETVAL\": %lld}\n",
                            type_str, evt->pid, evt->comm, evt->syscall_id, evt->retval);
                    }
                }
                fflush(log_file);
            }
            last_print_time = now;
        }
    }

    // 8. 종료 처리
    if(log_file) fclose(log_file);
    cleanup(rb, skel);

    return err < 0 ? -err : err;
}

// =================================================================
// 유틸리티 함수들
// =================================================================

static void sig_handler(int sig){
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args){
    if(level == LIBBPF_WARN){
        fprintf(stderr, "LIBBPF_WARN : ");
    }
    if(level <= LIBBPF_INFO) {
        return vfprintf(stderr, format, args);
    }
    return 0;
}

int handle_event(void *ctx, void *data, size_t data_sz){
    if(data_sz != sizeof(struct event)){
        fprintf(stderr, "!!!KERNEL-USERSPACE SIZE MISMATCH!!!\n");
        fprintf(stderr, "Kernel sent size : %zu, expected size : %zu\n", data_sz, sizeof(struct event));
        return 0; 
    }

    long current_count = atomic_load(&event_count);
    if(current_count >= EVENT_BUFFER_SIZE){
        return 0;
    }

    long index = atomic_fetch_add(&event_count, 1);
    if(index < EVENT_BUFFER_SIZE){
        memcpy(&event_buffer[index], data, sizeof(struct event));
    }

    return 0;
}

// [수정됨] 스켈레톤 구조체 이름 및 destroy 함수 이름 변경
void cleanup(struct ring_buffer *rb, struct sys_enter_and_out_bpf *skel){
    printf("\nCleaning up resources...\n");
    if (rb) ring_buffer__free(rb);
    if (skel) sys_enter_and_out_bpf__destroy(skel);
}