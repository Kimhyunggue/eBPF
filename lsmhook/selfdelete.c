#include <stdio.h>
#include <unistd.h>

void selfdel(char *binpath){
    printf("Trying to call unlink syscall to delete %s\n", binpath);

    if(unlink(binpath) == -1){
        fprintf(stderr, "self unlink failed for %s\n", binpath);
    }
    else{
        fprintf(stderr, "successfully self unlinked %s\n", binpath);
    }

}

int main(int argc, char *argv[]){
    char *binpath_to_del = argv[0];

    printf("Action before delete\n");
    sleep(3);

    selfdel(binpath_to_del);

    printf("Continue exectution since the process has still acess to this handle\n");
    sleep(3);

    printf("Program finished\n");

    return 0;
}