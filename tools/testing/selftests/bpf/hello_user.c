// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <bpf/libbpf.h>
#include "trace_helpers.h"
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

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
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;

	obj = bpf_object__open_file("/linux/samples/bpf/hello_kern.o", NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	prog = bpf_object__find_program_by_name(obj, "trace_enter_execve");
	if (!prog) {
		fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto cleanup;
	}

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

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
