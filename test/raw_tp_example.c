#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include "raw_tp_example.skel.h" 

struct event{
    __u32 pid;
    __u64 syscall_id;
    char comm[16];
};

 static volatile bool exiting = false;

 static void sig_handler(int sig){
 	exiting = true;
 }

 static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args){
 	return vfprintf(stderr, format, args);
 }

int handle_event(void *ctx, void *data, size_t data_sz){
	const struct event *e = data;
	printf("PID : %-6u COMM : %-16s SYSCALL ID : %llu\n", e->pid, e->comm, e->syscall_id);
	return 0;
}

int main(int argc, char **argv){
	struct raw_tp_example_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	// libbpf_set_print(libbpf_print_fn);

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

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if(!rb){
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Successfully Started!...\n");

	while(!exiting){
		err = ring_buffer__poll(rb, 100); // timeout : 100ms -> 100ms 이내로 데이터가 오지 않으면 NULL반환
		if(err < 0){
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

	// signal(SIGINT, sig_handler);
	// signal(SIGTERM, sig_handler);

	// printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output.\n");
	// printf("Press Ctrl+C to exit.\n");

	// while (!exiting) {
	// 	sleep(1);
	// }

cleanup:
	ring_buffer__free(rb);
	raw_tp_example_bpf__destroy(skel);
	return -err;
}