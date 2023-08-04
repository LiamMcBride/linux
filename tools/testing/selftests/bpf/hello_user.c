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

//----bpf program helpers----
//struct for easy transfer of bpf obj and link
struct bpf_link_and_obj {
	struct bpf_link* link;
	struct bpf_object* obj;
};

//destroys link and closes obj
void bpf_cleanup_program(struct bpf_link_and_obj bpf_lao) {
    bpf_link__destroy(bpf_lao.link);
    bpf_object__close(bpf_lao.obj);
}

//loads and attaches, returns a link and obj
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
    	bpf_object__close(bpf_lao.obj);
		struct bpf_link_and_obj bpf_la = {NULL, NULL};
    	return bpf_la;
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

//----test hello----
//reads the trace pipe
struct read_pipe_params {
	void* buffer;
	int num_lines;
} read_pipe_params;

void* read_pipe(void* buffer, int num_lines)
{
	char* buf = buffer;
	FILE* trace_fd;

	trace_fd = fopen("/sys/kernel/debug/tracing/trace_pipe", "r");
	if (trace_fd < 0)
		return NULL;

	int i = 0;
	do {
		fread(buf + i, sizeof(char), 1, trace_fd);
		i++;
		if (*(buf + i - 1) == '\n'){
			num_lines--;
		}
	} while(num_lines != 0);

	return NULL;
}

void trigger_execve_and_read_pipe(char* buf){
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
}

//test runner for hello
int hello_test(){
	printf("----[test hello]----\n");
	struct bpf_link_and_obj bpf_la;
	
	bpf_la = bpf_program_load_and_attach("/linux/samples/bpf/hello_kern.o",
		"trace_enter_execve");

	char buf[4096];
	trigger_execve_and_read_pipe(buf);
	if(strstr(buf, "Hello, BPF World!") != NULL)
		printf("[+] PASSED\n");
	else
		printf("[-] FAILED\n");

	printf("%s\n", buf);

	bpf_cleanup_program(bpf_la);
	return 0;
}

//----test syscall_tp----
//validates map values
static void syscall_tp_verify_map(int map_id)
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

//test runner for syscall_tp
int syscall_tp_test(){
	printf("----[test syscall_tp]----\n");
	struct bpf_link_and_obj bpf_las[6];
	char* progNames[] = {
		"trace_enter_open",
		"trace_enter_open_at",
		"trace_enter_open_at2",
		"trace_enter_exit",
		"trace_enter_exit_at",
		"trace_enter_exit_at2"
		};
	char* mapNames[] = {
		"enter_open_map",
		"exit_open_map"
		};

	for(int i = 0; i < 6; i++){
		char* mapName = mapNames[1];
		if (i < 3)
			mapName = mapNames[0];
		printf("[%s] with map: %s\n", progNames[i], mapName);
		bpf_las[i] = bpf_program_load_and_attach("/linux/samples/bpf/syscall_tp_kern.o",
			progNames[i]);
		int map_fd = bpf_object__find_map_fd_by_name(bpf_las[i].obj, mapName);
		printf("map file descriptor: %d\n", map_fd);

		if(map_fd < 0){
			printf("Error: finding a map in obj file failed\n");
		}

		//trigger open operation
		int fd = open("./hello_user.c", 0);
		if (fd < 0){
			printf("Error: Failed to open file");
		}
		close(fd);
		syscall_tp_verify_map(map_fd);
		printf("-------------------\n\n");
		
	}
	
	for(int i = 0; i < 6; i++){
		bpf_cleanup_program(bpf_las[i]);
	}

	return 0;
}

int sid1_test(){
	printf("----[test sid1]----\n");

	struct bpf_link_and_obj bpf_la;
	
	bpf_la = bpf_program_load_and_attach("/linux/samples/bpf/sid1_bpf_kern.o",
		"testing_tail_func");
	//include actual testing here
	int map_fd = bpf_object__find_map_fd_by_name(bpf_la.obj, "my_map");
	if (map_fd < 0){
		printf("Error: finding a map in obj file failed");
		bpf_cleanup_program(bpf_la);
		return 0;
	}
	char buf[4096];
	trigger_execve_and_read_pipe(buf);
	
	printf("buf: %s\n", buf);
	// read_pipe();
	bpf_cleanup_program(bpf_la);
	return 0;
}

int sample_test(){
	printf("----[test sample]----\n");

	struct bpf_link_and_obj bpf_la;
	
	bpf_la = bpf_program_load_and_attach("/linux/samples/bpf/filename.o",
		"program_name");
	//include actual testing here
	bpf_cleanup_program(bpf_la);
	return 0;
}

int main(int argc, char **argv)
{
	hello_test();
	// syscall_tp_test();
	sid1_test();
}
