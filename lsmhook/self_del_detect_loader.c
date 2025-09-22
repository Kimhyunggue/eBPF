#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include "loader.skel.h"

#define MAX_FILENAME_LEN 256
#define COMM_LEN 16

struct event_data{
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char exename[MAX_FILENAME_LEN];
    char filename[MAX_FILENAME_LEN];
    char comm[COMM_LEN];
};

static void setmemoryforuserspace(){
    struct rlimit newlimit={
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if(setrlimit(RLIMIT_MEMLOCK, &newlimit)){
        fprintf(stderr, "error in increasing memory for userspace app\n");
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event_data *event = data;

    if(data_sz < sizeof(struct event_data)) {
        fprintf(stderr, "Incomplete data recieived\n");
        return 1;
    }

    if(strncmp(event->exename, event->filename, MAX_FILENAME_LEN) == 0){
        printf("Self Delete Detected\n");
        printf("-------------------------------------\n");
        printf("PID : %d, PPID : %d, Command : %s\n", event->pid, event->ppid, event->comm);
        printf("Executable Name : %s\n", event->exename);
        printf("File is being deleted: %s\n", event->filename);
        printf("-------------------------------------\n");
    }

    return 0;
}

int main(){
    struct ring_buffer *rb = NULL;
    int err;
    setmemoryforuserspace();

    struct loader *skel = loader__open();
    loader__load(skel);
    loader__attach(skel);

    rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf_selfdel), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    while(1){
        err = ring_buffer__poll(rb, 100);
        if(err == -EINTR){
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }
    
}