#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sched_all.skel.h" 

static volatile bool exiting = false;
static volatile bool start_logging = false; // 💡 로깅 시작 스위치!

static void sig_handler(int sig) { exiting = true; }
static void sig_usr1_handler(int sig) { start_logging = true; } // 💡 신호 받으면 스위치 ON!

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) { return 0; }

int main(int argc, char **argv){
    struct sched_all_bpf *skel; 
    struct bpf_program *prog;
    int attached_count = 0;
    int failed_count = 0;
    int map_fd;

    libbpf_set_print(libbpf_print_fn);

    skel = sched_all_bpf__open_and_load();
    if (!skel) {
        printf("BPF 로드 실패!\n");
        return 1;
    }

    // 커널 버전 차이로 없는 훅이 있으면 튕기지 않고 스킵하며 개별 부착
    bpf_object__for_each_program(prog, skel->obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link || libbpf_get_error(link)) {
            failed_count++;
        } else {
            attached_count++;
        }
    }
    
    // 자기 자신(tracer) PID를 맵에 등록해서 카운트에서 제외
    __u32 zero = 0, my_pid = getpid();
    bpf_map__update_elem(skel->maps.my_pid_map, &zero, sizeof(zero), &my_pid, sizeof(my_pid), BPF_ANY);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGUSR1, sig_usr1_handler); // 💡 무전기(신호 수신기) 등록 완료!

    map_fd = bpf_map__fd(skel->maps.sched_counter);
    printf("🔥 %d개의 SCHED 단독 훅 부착 완료! (실패: %d개)\n", attached_count, failed_count);
    printf("⏳ 대기 중... (벤치마크 스크립트의 시작 신호 SIGUSR1을 기다립니다)\n");

    __u64 prev_count = 0;
    
    while(!exiting){
        sleep(1); 
        
        __u64 curr_count = 0;
        
        // 커널에서 현재 누적 카운터를 가져옴
        bpf_map_lookup_elem(map_fd, &zero, &curr_count);

        // 1초 동안 증가한 양(Delta) 계산
        __u64 diff = curr_count - prev_count;

        // 💡 스위치가 켜졌고, 카운트가 올랐을 때만 출력
        if (start_logging && diff > 0) {
            printf("[1초 누적] SCHED Events: %llu\n", diff);
        }

        prev_count = curr_count;
    }

    printf("\n안전하게 훅을 제거하고 종료합니다...\n");
    sched_all_bpf__destroy(skel);
    return 0;
}