// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <bpf/libbpf.h>
#include "trace_helpers.h"
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "bpf_setup.h"

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
	
	bpf_la = bpf_program_load_and_attach("/linux/samples/bpf/first_map_kern.o",
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

	printf("%s\n", buf);

	bpf_cleanup_program(bpf_la);
	return 0;
}
