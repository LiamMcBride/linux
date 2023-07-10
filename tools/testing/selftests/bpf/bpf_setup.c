#include <stdio.h>
#include <bpf/libbpf.h>
#include "trace_helpers.h"
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "bpf_setup.h"

void bpf_cleanup_program(struct bpf_link_and_obj bpf_lao) {
    bpf_link__destroy(bpf_lao.link);
    bpf_object__close(bpf_lao.obj);
}

/*
    obj_file looks like "/linux/samples/bpf/hello_kern.o"
    prog_name looks like "trace_enter_execve"
*/
struct bpf_link_and_obj bpf_program_load_and_attach(char* obj_file, char* prog_name){
    struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;

	obj = bpf_object__open_file(obj_file, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file [%s] failed\n", obj_file);
		return 0;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	prog = bpf_object__find_program_by_name(obj, prog_name);
	if (!prog) {
		fprintf(stderr, "ERROR: finding a prog [%s] in obj file failed\n", prog_name);
		goto cleanup;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed for [%s]\n", prog_name);
		link = NULL;
		goto cleanup;
	}

    goto success;

cleanup:
    bpf_cleanup_program(link, obj);
    return NULL;

success:
    struct bpf_link_and_obj bpf_lao;
    bpf_lao.link = link;
    bpf_lao.obj = obj;
    return bpf_lao;
}