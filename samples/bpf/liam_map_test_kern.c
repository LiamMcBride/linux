#include <linux/bpf.h>
#include "vmlinux.h"
#include <errno.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_ENTRIES 1000
#define MAX_NR_CPUS 1024

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, long);
    __uint(max_entries, MAX_ENTRIES);
} hash_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(void *ctx){
    u32 key = 10;
    long init_val = 1;
    long *value;
    int i;

    bpf_map_update_elem(&hash_map, &key, &init_val, BPF_ANY);
    key += 1;
    init_val += 10;

    return 0;
}