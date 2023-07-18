// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <bpf/libbpf.h>
#include "trace_helpers.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/bpf.h>
#include "bpf_setup.h"

int main(int argc, char **argv)
{
	struct bpf_link_and_obj bpf_la;
	struct bpf_map *map;
	struct data_t data;

	
	bpf_la = bpf_program_load_and_attach("/linux/samples/bpf/liam_map_test_kern.o",
		"trace_enter_execve");

	map = bpf_object__find_map_by_name(bpf_la.obj, "hash_map");
	if (!map) {
		printf("Failed to find map\n");
		bpf_cleanup_program(bpf_la);
		return 1;
	}

	struct bpf_map_info info = {};

	bpf_map_info(map, &info);

	struct bpf_map_lookup_elem_info lookup_info = {};
	u32 key = 10;
	int result = bpf_map_lookup_elem(map, &key, &data);
	if (result == 1){
		printf("Value found: name=%s, value=%d\n", data.name, data.value);
	}

	bpf_cleanup_program(bpf_la);
	return 0;
}
