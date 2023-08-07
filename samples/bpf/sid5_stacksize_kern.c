#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "trace_helpers.h"

#include <uapi/linux/bpf_perf_event.h>
#include <uapi/linux/perf_event.h>

#define SIZEOFSTACK 224 

static __attribute__((__noinline__)) int testing_bpf_to_bpf_calls2(void *ctx){
    
    unsigned char stack_space[SIZEOFSTACK] = {0};
    bpf_printk("testing_bpf_to_bpf_calls2: initial stack address of stack_space array which is also intial sp: %px", &stack_space[SIZEOFSTACK-1]);   
    bpf_printk("testing_bpf_to_bpf_calls2: final stack address of stack_space array which is also intial sp: %px", &stack_space[0]);   
    
    return 0;

}

SEC("tracepoint/syscalls/sys_enter_execve")
int testing_tail_func2(void *ctx){
    
    unsigned int stack_space[SIZEOFSTACK/4] = {0};
    bpf_printk("testing_tail_func: initial stack address of stack_space array which is also intial sp: %px", &stack_space[SIZEOFSTACK-1]);   
    bpf_printk("testing_tail_func: final stack address of stack_space array which is also intial sp: %px", &stack_space[0]);   
    
    testing_bpf_to_bpf_calls2(ctx); 
    return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 10);
	__uint(key_size, sizeof(__u32));
	__array(values, int (void *));
} prog_array_init2 SEC(".maps") = {
	.values = {
		[1] = (void *)&testing_tail_func2,
	},
};

static __attribute__((__noinline__)) int testing_bpf_to_bpf_calls(void *ctx){
    
    unsigned char stack_space[SIZEOFSTACK] = {0};
    bpf_printk("testing_bpf_to_bpf_calls: initial stack address of stack_space array which is also intial sp: %px", &stack_space[SIZEOFSTACK-1]);   
    bpf_printk("testing_bpf_to_bpf_calls: final stack address of stack_space array which is also intial sp: %px", &stack_space[0]);   
    
    bpf_tail_call(ctx, &prog_array_init2, 1);
    return 0;

}

SEC("tracepoint/syscalls/sys_enter_execve")
int testing_tail_func(void *ctx){
    
    unsigned int stack_space[SIZEOFSTACK/4] = {0};
    bpf_printk("testing_tail_func: initial stack address of stack_space array which is also intial sp: %px", &stack_space[SIZEOFSTACK-1]);   
    bpf_printk("testing_tail_func: final stack address of stack_space array which is also intial sp: %px", &stack_space[0]);   
    
    testing_bpf_to_bpf_calls(ctx); 
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
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(void *ctx){
    
    bpf_printk("Inside the trace_enter_execve kernel function\n");
    

    unsigned long x = bpf_get_stack_size();

    bpf_printk("testing bpf_get_stack_size helper %lx\n", x);

    unsigned char stack_space[SIZEOFSTACK] = {0};
    bpf_printk("initial stack address of stack_space array which is also intial sp: %px", &stack_space[SIZEOFSTACK-1]);   
    bpf_printk("final stack address of stack_space array which is also intial sp: %px", &stack_space[0]);   


    bpf_tail_call(ctx, &prog_array_init, 1);
    

    return 0;
}
char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;



