#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bpf_util.h"
#include "trace_helpers.h"

int main(int argc, char **argv)
{
    struct bpf_link *link = NULL;
    struct bpf_program *prog;
    struct bpf_object *obj;


    char filename[256];


    printf("Inside User Code Main Function\n");
    
    //writing kern filename to filename(array) buffer defined earlier
    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

    //opening the bpf ELF object file pointed by
    //the passed path and loading into the memory
    obj = bpf_object__open_file(filename, NULL);
    if(libbpf_get_error(obj)){
        fprintf(stderr, "Error: opening BPF obj file");
        return 0;
    }

    //finds the function that we want to call from the kern file
    prog = bpf_object__find_program_by_name(obj, "trace_enter_execve");
    if(!prog){
        fprintf(stderr,"finding the prog in the object file failed\n");
        goto cleanup;
    }
    
    /* load BPF program */
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        goto cleanup;
    }    
    //finding the map created in kern.c
    int my_map = bpf_object__find_map_fd_by_name(obj, "my_map");
    if(my_map<0){
        fprintf(stderr, "ERROR: finding the map in the object file failed\n");
        goto cleanup;
    }

    //attaching the bpf program to the tracepoint
    link = bpf_program__attach(prog);
    if(libbpf_get_error(link)){
        fprintf(stderr, "ERROR: bpf_program__attach failed : %ld\n", libbpf_get_error(link));
        link = NULL;
        goto cleanup;
    }else{
        fprintf(stderr, "Attachment is done\n");
    }

   read_trace_pipe();

    cleanup:
            bpf_link__destroy(link);
            bpf_object__close(obj);
            return 0;
    

}

