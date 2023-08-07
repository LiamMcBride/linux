#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// #include "trace_helpers.h


#define MAX_SIZE 1000
#define MAX_VAL 1000
#define SIZEOFSTACK 6


void test_func();
void testing_tail_func();
//struct for map

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SIZE);
    __type(key, int);
    __type(value, int);
}
my_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
void testing_tail_func2(void *ctx){

    bpf_printk("testing tail call func2");
	/* SIZEOFSTACK bytes */
    unsigned char stack_space[SIZEOFSTACK] = {0};

    /* 8 byte */
    unsigned long int i = 0;
    /* 8 byte */
    const char fmt_str[] = "x%x:%d\n";

    for(i = 0; i < SIZEOFSTACK; i++) {
        stack_space[i] = i % 255;
    }   

    for(i = 0; i < SIZEOFSTACK; i++) {
        bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + i, stack_space[i]);
    }  

    return;
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
void testing_tail_func(void *ctx){
    /* SIZEOFSTACK bytes */
    unsigned char stack_space[SIZEOFSTACK] = {0};

    /* 8 byte */
    unsigned long int i = 0;
    /* 8 byte */
    const char fmt_str[] = "x%x:%d\n";

    for(i = 0; i < SIZEOFSTACK; i++) {
        stack_space[i] = i % 255;
    }   

    for(i = 0; i < SIZEOFSTACK; i++) {
        bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + i, stack_space[i]);
    }   
	
//    bpf_tail_call(ctx, &prog_array_init, 1);
//    bpf_tail_call(ctx, &prog_array_init2, 1);
    test_func(ctx);
    
    return;

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

SEC("tracepoint/syscalls/sys_enter_execve")
void test_func(void *ctx){
	bpf_printk("Inside test func");
//	bpf_tail_call(ctx, &prog_array_init2, 1);

}



SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(void *ctx){

    static const char msg[] = "Inside my Testing Kernal Function";

    bpf_trace_printk(msg, sizeof(msg));
	
    bpf_printk("Testing BPF printk helper");
    // playing with ebpf Hash Map
    const int key = 10;
    int val = 100;
    bpf_map_update_elem(&my_map, &key, &val, BPF_ANY);

    int *result = bpf_map_lookup_elem(&my_map, &key);
    if (result){
        const char fmt_str[] = "Found: %d\n";        
        bpf_trace_printk(fmt_str,sizeof(fmt_str), *result);
    }
    else{
        static const char msg1[] = "Not Found\n";
        bpf_trace_printk(msg1, sizeof(msg1));
    }

    //playing with bpf tailcalls
    bpf_tail_call(ctx, &prog_array_init, 1);
    
    return 0;

}


char _license[] SEC("license") = "GPL";
// u32 _version SEC("version") = LINUX_VERSION_CODE;



