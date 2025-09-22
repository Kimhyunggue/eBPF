#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/resource.h>

#include "loader.skel.h"

static void setmemoryforuserspace(){
    struct rlimit newlimit={
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if(setrlimit(RLIMIT_MEMLOCK, &newlimit)){
        fprintf(stderr, "error in increasing memory for userspace app\n");
    }
}

int main(){
    
    setmemoryforuserspace();

    struct loader *skel = loader__open();
    loader__load(skel);
    loader__attach(skel);

    printf("Successfully loaded and attached the BPF program\n");

    while(1){
        sleep(2);
    }
}