#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "all_syscalls.skel.h" 

static volatile bool exiting = false;
static volatile bool start_logging = false; // 💡 벤치마크 시작 신호 대기용 스위치

static void sig_handler(int sig) { exiting = true; }
static void sig_usr1_handler(int sig) { start_logging = true; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) { return 0; }

int main(int argc, char **argv){
    struct all_syscalls_bpf *skel; 
    struct bpf_program *prog;
    int attached_count = 0, failed_count = 0, map_fd;

    libbpf_set_print(libbpf_print_fn);

    skel = all_syscalls_bpf__open_and_load();
    if (!skel) {
        printf("BPF 스켈레톤 로드 실패!\n");
        return 1;
    }

    // 커널 버전 차이로 에러 나는 훅은 무시하고 끝까지 부착
    bpf_object__for_each_program(prog, skel->obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link || libbpf_get_error(link)) {
            failed_count++;
        } else {
            attached_count++;
        }
    }

    // 💡 내 프로세스(tracer) PID 등록하여 카운팅에서 제외
    __u32 zero = 0, my_pid = getpid();
    bpf_map__update_elem(skel->maps.my_pid_map, &zero, sizeof(zero), &my_pid, sizeof(my_pid), BPF_ANY);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGUSR1, sig_usr1_handler); // 💡 무전기 등록

    map_fd = bpf_map__fd(skel->maps.syscalls_counter);
    printf("🔥 %d개의 SYSCALL 단독 훅 부착 완료! (실패: %d개)\n", attached_count, failed_count);
    printf("⏳ 대기 중... (벤치마크 스크립트의 시작 신호를 기다립니다)\n");

    __u64 prev_count = 0;
    int num_cpus = libbpf_num_possible_cpus();
    
    while(!exiting){
        sleep(1); 
        
        __u64 curr_count = 0;
        __u64 values[num_cpus];
        
        // 💡 모든 코어의 배열을 통째로 읽어와서 합산
        if (bpf_map_lookup_elem(map_fd, &zero, values) == 0) {
            for (int i = 0; i < num_cpus; i++) {
                curr_count += values[i];
            }
        }

        __u64 diff = curr_count - prev_count;

        // 신호를 받았고, 카운트가 올랐을 때만 화면 출력
        if (start_logging && diff > 0) {
            printf("[1초 누적] SYSCALL Events: %llu\n", diff);
        }
        prev_count = curr_count;
    }

    printf("\n안전하게 훅을 제거하고 종료합니다...\n");
    all_syscalls_bpf__destroy(skel);
    return 0;
}