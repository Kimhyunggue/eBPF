#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdatomic.h>
#include <bpf/libbpf.h>
#include "raw_tp_example.skel.h"


struct event{
    __u32 pid;
    __u64 syscall_id;
    char comm[16];
};


#define EVENT_BUFFER_SIZE 8192
struct event event_buffer[EVENT_BUFFER_SIZE];
static atomic_long event_index = 0;

static volatile bool exiting = false;

static void sig_handler(int sig){
 	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args){
	return 0;
	// return vfprintf(stderr, format, args);
}

int handle_event(void *ctx, void *data, size_t data_sz){
	if(atomic_load(&event_index) >= EVENT_BUFFER_SIZE){ //buffer가 꽉 찼으면 종료
		return 0;
	}
	// const struct event *e = data;
	// printf("PID : %-6u COMM : %-16s SYSCALL ID : %llu\n", e->pid, e->comm, e->syscall_id);
	long index = atomic_fetch_add(&event_index, 1);
	
	if(index < EVENT_BUFFER_SIZE){
		memcpy(&event_buffer[event_index], data, sizeof(struct event));
	}

	return 0;
}

int main(int argc, char **argv){
	struct raw_tp_example_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;
	time_t last_print_time;

	libbpf_set_print(libbpf_print_fn);

	skel = raw_tp_example_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	err = raw_tp_example_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	
	__u32 zero = 0;
	__u32 my_pid = getpid();

	err = bpf_map__update_elem(skel->maps.my_pid_map, &zero, sizeof(zero), &my_pid, sizeof(my_pid), BPF_ANY);
	if(err < 0){
		fprintf(stderr, "Failed to update my_pid_map : %d, %s\n", err, strerror(-err));
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if(!rb){
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	printf("Successfully Started!.....Press Ctrl+C to exit\n");
	last_print_time = time(NULL);

	while(!exiting){
		err = ring_buffer__poll(rb, 1000); // timeout : 1000ms -> 1000ms 이내로 데이터가 오지 않으면 NULL반환

		if(err < 0 && err != -EINTR){
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}

		time_t now = time(NULL);
		if(now - last_print_time >= 1){ // 1초에 한번씩 출력
			long count = atomic_exchange(&event_index, 0);

			if(count > 0){
				printf("----- Events in Last period (~1s) : %ld ------\n", count);

				long print_limit = (count < 10) ? count : 10;
				for (long i = 0; i < print_limit; i++) {
					struct event *evt = &event_buffer[i];
					if(evt->pid == 0) // PID 0은 커널 스케쥴러이므로 무시
						continue;
					printf("  -> PID: %-6u COMM: %-16s SYSCALL_ID: %llu\n",
						evt->pid, evt->comm, evt->syscall_id);
				}
				if (count > 10) {
					printf("  ... and %ld more events.\n", count - 10);
				}
			
				// for(long i = 0; i < count; i++){
				// 	struct event *e = &event_buffer[i];
				// 	printf("PID : %-6u COMM : %-16s SYSCALL ID : %llu\n", e->pid, e->comm, e->syscall_id);
				// }
			}
			last_print_time = now;
		}

		// long count = atomic_exchange(&event_index, 0);

		// if(count > 0){
		// 	printf("----- Events in Last period (~1s) : %ld ------\n", count);
			
		// 	for(long i = 0; i < count; i++){
		// 		struct event *e = &event_buffer[i];
		// 		printf("PID : %-6u COMM : %-16s SYSCALL ID : %llu\n", e->pid, e->comm, e->syscall_id);
		// 	}
		// }
	}

	// printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output.\n");
	// printf("Press Ctrl+C to exit.\n");

	// while (!exiting) {
	// 	sleep(1);
	// }

cleanup:
	printf("\nExiting...\n");
	ring_buffer__free(rb);
	raw_tp_example_bpf__destroy(skel);
	return -err;
}