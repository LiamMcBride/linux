#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// #include "trace_helpers.h"

#if defined(CONFIG_FUNCTION_TRACER)
#define CC_USING_FENTRY

#endif
#include <linux/kprobes.h>
#define MAX_DICT_SIZE 1000000 
#define MAX_DICT_VAL  100


struct map_locked_value {
    int value;
    struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DICT_SIZE);
	__type(key, u32);
	__type(value, struct map_locked_value);
} counter_hash_map SEC(".maps");


SEC("fentry/__x64_sys_execve")
int testing_tail_func(void *ctx){
    bpf_printk("inside first tail-call");
    return 0;

}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 10);
	__uint(key_size, sizeof(__u32));
	__array(values, int (void *));
} prog_array_init SEC(".maps") = {
	.values = {
		[1] = (void *)&testing_tail_func,
	},
};

static int spinlock(void *ctx)
{
	int key = 1;  
	
    struct map_locked_value *val = bpf_map_lookup_elem(&counter_hash_map, &key);
	
    if(!val)
		return 1;
	
    bpf_spin_lock(&val->lock);
	val->value++;
	bpf_spin_unlock(&val->lock);

    bpf_tail_call(ctx, &prog_array_init, 1);
	
    return 0;
}

static int test_tailcalls(u32 index, void *ctx){
    bpf_printk("printing loops");
    return 0;
}

SEC("fentry/__x64_sys_execve")
int trace_enter_execve(struct pt_regs *ctx)
{	
    
	struct map_locked_value value= {} ;   
	int key=1;
	bpf_map_update_elem(&counter_hash_map , &key,&value, BPF_ANY);
	
    bpf_printk("before spinlock function");
	//spinlock(ctx);
	

	
    struct map_locked_value *val = bpf_map_lookup_elem(&counter_hash_map, &key);
	
    if(!val)
		return 0;
	
    bpf_spin_lock(&val->lock);
	val->value++;
	bpf_spin_unlock(&val->lock);

    bpf_tail_call(ctx, &prog_array_init, 1);
    
    return 0;	
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
