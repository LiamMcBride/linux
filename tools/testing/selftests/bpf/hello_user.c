// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <bpf/libbpf.h>
#include "trace_helpers.h"
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
// #include "bpf_setup.h"

// holds bpf_link and bpf_object pointers for easy return
struct bpf_link_and_obj {
    struct bpf_link* link;
    struct bpf_object* obj;
} bpf_link_and_obj;

// called when program is finished and link and object need to be cleaned
void bpf_cleanup_program(struct bpf_link_and_obj bpf_lao) {
    bpf_link__destroy(bpf_lao.link);
    bpf_object__close(bpf_lao.obj);
}

/*
    responsible for opening, loading, and attaching bpf prog from file and name
	obj_file looks like "/linux/samples/bpf/hello_kern.o"
    prog_name looks like "trace_enter_execve"
*/
struct bpf_link_and_obj bpf_program_load_and_attach(char* obj_file, char* prog_name){
	struct bpf_program *prog;
    struct bpf_link_and_obj bpf_lao;

	bpf_lao.obj = bpf_object__open_file(obj_file, NULL);
	if (libbpf_get_error(bpf_lao.obj)) {
		fprintf(stderr, "ERROR: opening BPF object file [%s] failed\n", obj_file);
		struct bpf_link_and_obj bpf_la = {NULL, NULL};
		return bpf_la;
	}

	if (bpf_object__load(bpf_lao.obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	prog = bpf_object__find_program_by_name(bpf_lao.obj, prog_name);
	if (!prog) {
		fprintf(stderr, "ERROR: finding a prog [%s] in obj file failed\n", prog_name);
		goto cleanup;
	}

	bpf_lao.link = bpf_program__attach(prog);
	if (libbpf_get_error(bpf_lao.link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed for [%s]\n", prog_name);
		bpf_lao.link = NULL;
		goto cleanup;
	}

    goto success;

cleanup:
	bpf_cleanup_program(bpf_lao);
	struct bpf_link_and_obj bpf_la = {NULL, NULL};
    return bpf_la;

success:
    return bpf_lao;
}

void* read_pipe(void* buffer)
{
	char* buf = buffer;
	FILE* trace_fd;

	trace_fd = fopen("/sys/kernel/debug/tracing/trace_pipe", "r");
	if (trace_fd < 0)
		return NULL;

	int i = 0;
	while(i < 86){
		fread(buf + i, sizeof(char), 1, trace_fd);
		i++;
	}

	return NULL;
}

bool verify_output(char* output){
	return strstr(output, "Hello, BPF World!") != NULL;
}

int main(int argc, char **argv)
{
	struct bpf_link_and_obj bpf_la;
	
	bpf_la = bpf_program_load_and_attach("/linux/samples/bpf/hello_kern.o",
		"trace_enter_execve");

	char buf[4096];
	pthread_t output_thread;
	if(pthread_create(&output_thread, NULL, 
		(void*)read_pipe, (void*)buf) < 0){
		fprintf(stderr, "ERROR: reading thread failed to create\n");
	}
	sleep(.5);
	FILE* ls_pipe = popen("ls", "r");
	if(ls_pipe == NULL){
		perror("Error executing ls command");
	}
	pthread_cancel(output_thread);
	
	pthread_join(output_thread, NULL);
	if(verify_output(buf))
		printf("[+] PASSED\n");
	else
		printf("[-] FAILED\n");

	printf("%s\n", buf);

	bpf_cleanup_program(bpf_la);
	return 0;
}
