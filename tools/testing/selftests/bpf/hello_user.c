// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <bpf/libbpf.h>
#include "trace_helpers.h"
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include "testing_helpers.h"
// #include "bpf_setup.h"

struct bpf_link_and_obj {
	struct bpf_link* link;
	struct bpf_object* obj;
};

void bpf_cleanup_program(struct bpf_link_and_obj bpf_lao) {
    bpf_link__destroy(bpf_lao.link);
    bpf_object__close(bpf_lao.obj);
}

struct bpf_link_and_obj bpf_program_load_and_attach(char* obj_file, char* prog_name){
	struct bpf_program *prog;
    struct bpf_link_and_obj bpf_lao;

	bpf_lao.obj = bpf_object__open_file(obj_file, NULL);
	if (libbpf_get_error(bpf_lao.obj)) {
		printf("ERROR: opening BPF object file [%s] failed\n", obj_file);
		struct bpf_link_and_obj bpf_la = {NULL, NULL};
		return bpf_la;
	}

	if (bpf_object__load(bpf_lao.obj)) {
		printf("ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	prog = bpf_object__find_program_by_name(bpf_lao.obj, prog_name);
	if (!prog) {
		printf("ERROR: finding a prog [%s] in obj file failed\n", prog_name);
		goto cleanup;
	}

	bpf_lao.link = bpf_program__attach(prog);
	if (libbpf_get_error(bpf_lao.link)) {
		printf("ERROR: bpf_program__attach failed for [%s]\n", prog_name);
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

int hello_test(){
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

int sample_test(){
	struct bpf_link_and_obj bpf_la;
	
	bpf_la = bpf_program_load_and_attach("/linux/samples/bpf/filename.o",
		"program_name");
	//include actual testing here
	bpf_cleanup_program(bpf_la);
	return 0;
}

/*
map1_fds: 5
prog #0: map ids 4 5
map1_fds: -1404642640
map1_fds: -1404642640
map1_fds: -1404642640
Verification Index: 0, map0_fd: 4 map1_fd: -1404642640
Looking up map [map_id: 4]
verify map:4 val: 5
Looking up map [map_id: -1404642640]
map_lookup failed: Bad file descriptor
*/

static void verify_map(int map_id)
{
	__u32 key = 0;
	__u32 val;
	printf("Looking up map [map_id: %d]\n", map_id);
	if (bpf_map_lookup_elem(map_id, &key, &val) != 0) {
		fprintf(stderr, "map_lookup failed: %s\n", strerror(errno));
		return;
	}
	if (val == 0) {
		fprintf(stderr, "failed: map #%d returns value 0\n", map_id);
		return;
	}

	printf("verify map:%d val: %d\n", map_id, val);

	val = 0;
	if (bpf_map_update_elem(map_id, &key, &val, BPF_ANY) != 0) {
		fprintf(stderr, "map_update failed: %s\n", strerror(errno));
		return;
	}
}

int syscall_tp_sys_enter_open_test(){
	struct bpf_link_and_obj bpf_la;
	
	bpf_la = bpf_program_load_and_attach("/linux/samples/bpf/syscall_tp_kern.o",
		"trace_enter_open");
	//include actual testing here
	int map_fd = bpf_object__find_map_fd_by_name(bpf_la.obj, "enter_open_map");
	printf("map file descriptor: %d\n", map_fd);

	if(map_fd < 0){
		printf("Error: finding a map in obj file failed\n");
		goto cleanup;
	}

	//trigger open operation
	int fd = open("./hello_user.c", 0);
	if (fd < 0){
		printf("Error: Failed to open file");
	}
	close(fd);
	system("cat ./hello_user.c");
	sleep(1);
	verify_map(map_fd);


	//end of testing
cleanup:
	bpf_cleanup_program(bpf_la);
	return 0;
}

int main(int argc, char **argv)
{
	hello_test();
	syscall_tp_sys_enter_open_test();
}
