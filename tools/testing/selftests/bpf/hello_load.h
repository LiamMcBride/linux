#ifndef FLOW_DISSECTOR_LOAD
#define FLOW_DISSECTOR_LOAD

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include "testing_helpers.h"

static inline int bpf_hello_load(struct bpf_object **obj,
				const char *path,
				const char *prog_name,
				int *prog_fd)
{
    printf("Hello User\n");
	struct bpf_program *prog, *main_prog;
	int ret, fd;

	ret = bpf_prog_test_load(path, BPF_PROG_ATTACH, obj,
			    prog_fd);
    printf("BPF_PROG_TEST_LOAD ret: %d\n", ret);
	if (ret)
		return ret;

	main_prog = bpf_object__find_program_by_name(*obj, prog_name);
    printf("BPF_OBJECT__FIND_PROGRAM_BY_NAME ret: %p\n", main_prog);
    if (!main_prog)
		return -1;

	*prog_fd = bpf_program__fd(main_prog);
    printf("BPF_PROGRAM__FD ret: %d\n", ret);
    if (*prog_fd < 0)
		return -1;


	bpf_object__for_each_program(prog, *obj) {
		fd = bpf_program__fd(prog);
		if (fd < 0)
			return fd;
	}

	return 0;
}

#endif