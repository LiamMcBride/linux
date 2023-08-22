// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
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
//reads the trace pipe
struct read_pipe_params {
	char* buffer;
	int num_lines;
} read_pipe_params;
//struct for easy transfer of bpf obj and link
struct bpf_link_and_obj {
	struct bpf_link* link;
	struct bpf_object* obj;
};

struct bpf_test {
	char* name;
	char* file;
	char** desired_outputs;
	int trace_pipe;
	int map;
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


void clean_trace_pipe(){
	// system("echo -n '' > /sys/kernel/debug/tracing/trace_pipe");
	printf("Cleaning trace pipe:\n");
	system("timeout 2 cat /sys/kernel/debug/tracing/trace_pipe > /dev/null");
	printf("-----------------------\n");
}

void* read_pipe(void* params)
{
	struct read_pipe_params* rpp = (struct read_pipe_params*) params;
	char* buf = rpp->buffer;
	int num_lines = rpp->num_lines;
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

	fclose(trace_fd);

	return NULL;
}

void trigger_execve(){
	FILE* ls_pipe = popen("ls", "r");
	if(ls_pipe == NULL){
		perror("Error executing ls command");
	}
}

void trigger_execve_and_read_pipe(char* buf, int num_lines){
	pthread_t output_thread;
	struct read_pipe_params* rpp = malloc(sizeof(struct read_pipe_params));
	rpp->buffer = buf;
	rpp->num_lines = num_lines;

	// clean_trace_pipe();

	if(pthread_create(&output_thread, NULL, 
		(void*)read_pipe, (void*)rpp) < 0){
		fprintf(stderr, "ERROR: reading thread failed to create\n");
	}
	sleep(.5);
	trigger_execve();
	pthread_cancel(output_thread);
	
	pthread_join(output_thread, NULL);
}

//----test syscall_tp----
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

int prog_test_test(struct bpf_test test){
	char* name = strrchr(test.file, '/');
	name = name + 1;
	printf("----[test %s]----\n", name);

	// union bpf_attr* attr;
	// attr->prog_fd
	// attr->
	/*
	Run the eBPF program associated with the prog_fd
	a repeat number of times against a provided
	program context ctx_in and data data_in,
	and return the modified program context ctx_out,
	data_out (for example, packet data), result of
	the execution retval, and duration of the test
	run.
	*/
	//int bpf_prog_test_run_opts (int prog_fd, struct bpf_test_run_opts *opts)
	int prog_fd;
	struct bpf_test_run_opts opts = {
		.data_in = NULL,
		.data_size_in = sizeof(opts.data_in),
	};

	struct bpf_program *prog;
    struct bpf_link_and_obj bpf_lao;

	char* obj_file = "/linux/samples/bpf/hello_kern.o";
	char* prog_name = "trace_enter_execve";

	bpf_lao.obj = bpf_object__open_file(obj_file, NULL);
	if (libbpf_get_error(bpf_lao.obj)) {
		printf("ERROR: opening BPF object file [%s] failed\n", obj_file);
		return 1;
	}

	if (bpf_object__load(bpf_lao.obj)) {
		printf("ERROR: loading BPF object file failed\n");
		return 1;
	}

	prog = bpf_object__find_program_by_name(bpf_lao.obj, prog_name);
	if (!prog) {
		printf("ERROR: finding a prog [%s] in obj file failed\n", prog_name);
    	bpf_object__close(bpf_lao.obj);
    	return 1;
	}

	bpf_prog
	



	int ret = bpf_prog_test_run_opts(prog_fd, &opts);

	return 0;
}

//test runner for hello
int universal_test(struct bpf_test test){
	char* name = strrchr(test.file, '/');
	name = name + 1;

	printf("----[test %s]----\n", name);
	struct bpf_link_and_obj bpf_la;
	
	bpf_la = bpf_program_load_and_attach(test.file,
		test.name);

	int line_num = 0;

	while(test.desired_outputs[line_num] != NULL){
		line_num++;
	}

	char buf[4096];
	// trigger_execve_and_read_pipe(buf, 1);
	trigger_execve();
	sleep(0.5);
	bpf_cleanup_program(bpf_la);
	
	struct read_pipe_params* rpp = malloc(sizeof(struct read_pipe_params));
	rpp->buffer = buf;
	rpp->num_lines = line_num;

	read_pipe(rpp);

	int count = 0;
	int correct = 1;

	while(test.desired_outputs[count] != NULL){
		if(!strstr(buf, test.desired_outputs[count])){
			correct = 0;
			break;
		}
		count++;
	}

	if(correct == 1){
		printf("[+] PASSED\n");
	}
	else{
		printf("[-] FAILED\n");
	}
	printf("%s\n", buf);

	return 0;
}

int main(int argc, char **argv)
{
	int test_count = 4;
	struct bpf_test* tests = calloc(sizeof(struct bpf_test), test_count);
	(tests + 0)->name = "trace_enter_execve";
	(tests + 0)->file = "/linux/samples/bpf/hello_kern.o";
	(tests + 0)->desired_outputs = calloc(sizeof(char*), 2);
	(tests + 0)->desired_outputs[0] = "Hello, BPF World!";
	(tests + 0)->trace_pipe = 1;
	(tests + 0)->map = 0;

	(tests + 1)->name = "trace_enter_execve";
	(tests + 1)->file = "/linux/samples/bpf/sid1_bpf_kern.o";
	(tests + 1)->desired_outputs = calloc(sizeof(char*), 4);
	(tests + 1)->desired_outputs[0] = "Inside my Testing Kernal Function";
	(tests + 1)->desired_outputs[1] = "Testing BPF printk helper";
	(tests + 1)->desired_outputs[2] = "Found:";
	(tests + 1)->trace_pipe = 1;
	(tests + 1)->map = 0;
	
	(tests + 2)->name = "trace_enter_execve";
	(tests + 2)->file = "/linux/samples/bpf/sid2_sp_kern.o";
	(tests + 2)->desired_outputs = calloc(sizeof(char*), 3);
	(tests + 2)->desired_outputs[0] = "Inside the kernel function";
	(tests + 2)->desired_outputs[1] = "Testing BPF printk helper";
	(tests + 2)->trace_pipe = 1;
	(tests + 2)->map = 0;
	
	(tests + 3)->name = "trace_enter_execve";
	(tests + 3)->file = "/linux/samples/bpf/sid3_tailcalls_kern.o";
	(tests + 3)->desired_outputs = calloc(sizeof(char*), 3);
	(tests + 3)->desired_outputs[0] = "Inside the trace_enter_execve kernel function";
	(tests + 3)->desired_outputs[1] = "Testing BPF printk helper";
	(tests + 3)->trace_pipe = 1;
	(tests + 3)->map = 0;








	clean_trace_pipe();
	for(int i = 0; i < test_count; i++){
		universal_test(tests[i]);
	}

	//cleanup
	for(int i = 0; i < test_count; i++){
		tests[i].name = NULL;
		tests[i].file = NULL;
		free(tests[i].name);
		free(tests[i].file);
		int k = 0;
		while(tests[i].desired_outputs[k] != NULL){
			tests[i].desired_outputs[k] = NULL;
			free(tests[i].desired_outputs[k]);
		}
		tests[i].desired_outputs = NULL;
		free(tests[i].desired_outputs);
	}
	tests = NULL;
	free(tests);
}
