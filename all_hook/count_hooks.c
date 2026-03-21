#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "count_hooks.skel.h" 

static volatile bool exiting = false;
static volatile bool start_logging = false; 

static void sig_handler(int sig) { exiting = true; }
static void sig_usr1_handler(int sig) { start_logging = true; } 
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) { return 0; }

int main(int argc, char **argv){
    struct count_hooks_bpf *skel; 
    struct bpf_program *prog;
    int attached_count = 0, failed_count = 0;
    int map_fd;

    libbpf_set_print(libbpf_print_fn);
    skel = count_hooks_bpf__open_and_load();
    if (!skel) return 1;

    bpf_object__for_each_program(prog, skel->obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link || libbpf_get_error(link)) {
            failed_count++;
        } else {
            attached_count++;
        }
    }

    // 💡 내 프로세스 PID 등록 (무한 루프 폭주 방지)
    __u32 zero = 0, my_pid = getpid();
    bpf_map__update_elem(skel->maps.my_pid_map, &zero, sizeof(zero), &my_pid, sizeof(my_pid), BPF_ANY);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGUSR1, sig_usr1_handler);

    map_fd = bpf_map__fd(skel->maps.counters);
    printf("🔥 %d개의 고속 카운팅 훅 부착 완료! (실패: %d개)\n", attached_count, failed_count);
    printf("⏳ 대기 중... (벤치마크 스크립트의 시작 신호를 기다립니다)\n");

    __u64 prev_counts[3] = {0, 0, 0};
    int num_cpus = libbpf_num_possible_cpus(); // 💡 코어 개수 확인
    
    while(!exiting){
        sleep(1); 
        __u64 curr_counts[3] = {0, 0, 0};
        __u64 values[num_cpus];
        
        // 💡 0(Syscalls), 1(Sched), 2(Kmem) 방을 돌면서 모든 CPU 값 합산
        for (__u32 key = 0; key < 3; key++) {
            if (bpf_map_lookup_elem(map_fd, &key, values) == 0) {
                for (int i = 0; i < num_cpus; i++) {
                    curr_counts[key] += values[i];
                }
            }
        }

        if (start_logging) {
            __u64 diff_sys = curr_counts[0] - prev_counts[0];
            __u64 diff_sched = curr_counts[1] - prev_counts[1];
            __u64 diff_kmem = curr_counts[2] - prev_counts[2];

            if (diff_sys > 0 || diff_sched > 0 || diff_kmem > 0) {
                printf("[1초 누적] Syscalls: %llu | Sched: %llu | Kmem: %llu\n", diff_sys, diff_sched, diff_kmem);
            }
        }

        prev_counts[0] = curr_counts[0];
        prev_counts[1] = curr_counts[1];
        prev_counts[2] = curr_counts[2];
    }

    printf("\n안전하게 훅을 제거하고 종료합니다...\n");
    count_hooks_bpf__destroy(skel);
    return 0;
}