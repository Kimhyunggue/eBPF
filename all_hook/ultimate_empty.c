#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <bpf/libbpf.h>
#include "ultimate_empty.skel.h" 

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) { return 0; }

int main(int argc, char **argv){
    struct ultimate_empty_bpf *skel; 
    struct bpf_program *prog;
    int attached_count = 0;

    libbpf_set_print(libbpf_print_fn);

    skel = ultimate_empty_bpf__open_and_load();
    if (!skel) {
        printf("BPF 로드 실패!\n");
        return 1;
    }

    // 에러 나는 훅은 쿨하게 스킵하고 끝까지 부착
    bpf_object__for_each_program(prog, skel->obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (link) {
            attached_count++;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("🔥 %d개의 깡통 훅(syscalls + kmem + sched) 부착 완료!\n", attached_count);
    printf("순수 진입/종료 오버헤드 측정 대기 중... (종료는 Ctrl+C)\n");

    while(!exiting){
        sleep(1); 
    }

    printf("\n종료합니다...\n");
    ultimate_empty_bpf__destroy(skel);
    return 0;
}
