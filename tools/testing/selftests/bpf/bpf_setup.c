#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <stdlib.h>
#include "bpf_setup.h"

void bpf_cleanup_program(struct bpf_link_and_obj bpf_lao) {
    bpf_link__destroy(bpf_lao.link);
    bpf_object__close(bpf_lao.obj);
}

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