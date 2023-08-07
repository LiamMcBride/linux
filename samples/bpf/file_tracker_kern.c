// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2017 Facebook
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct syscalls_enter_open_args {
	unsigned long long unused;
	long syscall_nr;
	long filename_ptr;
	long flags;
	long mode;
};

struct syscalls_exit_open_args {
	unsigned long long unused;
	long syscall_nr;
	long ret;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, long);
	__uint(max_entries, 1);
} enter_open_map SEC(".maps");

static __always_inline void count(void *map)
{
	int key = 0;
	long *value, init_val = 1;

	value = bpf_map_lookup_elem(map, &key);
	if (value)
		*value = *value + 1;
	else
		bpf_map_update_elem(map, &key, &init_val, BPF_NOEXIST);
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_enter_open(struct syscalls_enter_open_args *ctx)
{
	count(&enter_open_map);
	return 0;
}