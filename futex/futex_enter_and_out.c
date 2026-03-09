#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <stdatomic.h>
#include <bpf/libbpf.h>
// 1. 헤더 파일명 변경
#include "futex_enter_and_out.skel.h" 

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

// 2. 구조체 이름 변경
void cleanup(struct ring_buffer *rb, struct futex_enter_and_out_bpf *skel){
    if (rb) ring_buffer__free(rb);
    // 3. destroy 함수 이름 변경
    if (skel) futex_enter_and_out_bpf__destroy(skel);
}

int main(int argc, char **argv){
    // 4. 구조체 이름 변경
    struct futex_enter_and_out_bpf *skel; 
    struct ring_buffer *rb = NULL;
    FILE *log_file = NULL;

    libbpf_set_print(libbpf_print_fn);

    // 5. open_and_load 함수 이름 변경
    skel = futex_enter_and_out_bpf__open_and_load();
    if (!skel) return 1;

    // 6. attach 함수 이름 변경
    if (futex_enter_and_out_bpf__attach(skel)) {
        cleanup(rb, skel);
        return 1;
    }
    
    __u32 zero = 0, my_pid = getpid();
    bpf_map__update_elem(skel->maps.my_pid_map, &zero, sizeof(zero), &my_pid, sizeof(my_pid), BPF_ANY);

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if(!rb) { cleanup(rb, skel); return 1; }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    log_file = fopen("futex_trace.log", "w");
    if(!log_file) { cleanup(rb, skel); return 1; }

    printf("Monitoring ONLY futex syscalls. Press Ctrl+C to exit...\n");
    time_t last_print_time = time(NULL);

    while(!exiting){
        ring_buffer__poll(rb, 1000); 

        time_t now = time(NULL);
        if(now - last_print_time >= 1){ 
            long count = atomic_exchange(&event_count, 0);

            if(count > 0){
                for (long i = 0; i < count; i++) {
                    struct event *evt = &event_buffer[i];
                    if(evt->pid == 0) continue; 

                    int cmd = evt->futex_op & 0x7F;
                    const char* op_str = (cmd == 0) ? "WAIT" : (cmd == 1) ? "WAKE" : "OTHER";

                    if (evt->is_enter) {
                        fprintf(log_file, "ENTER | PID: %-6u | COMM: %-15s | OP: %s\n",
                            evt->pid, evt->comm, op_str);
                    } else {
                        fprintf(log_file, "EXIT  | PID: %-6u | COMM: %-15s | RET: %lld\n",
                            evt->pid, evt->comm, evt->retval);
                    }
                }
                fflush(log_file);
            }
            last_print_time = now;
        }
    }

    fclose(log_file);
    cleanup(rb, skel);
    return 0;
}