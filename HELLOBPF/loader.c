#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>

#include "loader.skel.h"

int main(){
    struct rlimit newlimit = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if(setrlimit(RLIMIT_MEMLOCK, &newlimit)){
        fprintf(stderr, "memory allocation failed\n");
    }
    //open
    struct loader *obj = loader__open();
    
    //load
    loader__load(obj);

    //attach
    loader__attach(obj);

    while(1){
        sleep(1);
    }

    return 0;
}