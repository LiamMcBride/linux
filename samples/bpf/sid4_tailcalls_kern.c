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

#define MAX_SIZE 1000
#define MAX_VAL 1000
#define SIZEOFSTACK 208

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SIZE);
    __type(key, int);
    __type(value, int);
}
my_map SEC(".maps");

#define RTAIL_CALL(X, Y) \
static __attribute__((__noinline__)) int testing_bpf_to_bpf_calls ## X(void *ctx){ \
    unsigned char stack_space[SIZEOFSTACK] = {0}; \
    unsigned long int i = 0; \
    const char fmt_str[] = "x%x:%d\n"; \
    for(i = 0; i < SIZEOFSTACK; i++) { \
        stack_space[i] = i % 255; \
    }   \
        bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + 0, stack_space[0]); \
    for(i = 0; i < SIZEOFSTACK; i++) { \
    }   \
    unsigned long x = bpf_get_stack_size(); \
    bpf_printk("testing_tail_func%s: bpf_get_stack_size helper %lx\n", #X,x);\
    bpf_tail_call(ctx, &prog_array_init ## Y, 1); \
    return 0; \
} \
SEC("tracepoint/syscalls/sys_enter_execve") \
int testing_tail_func ## X(void *ctx){ \
    unsigned char stack_space[SIZEOFSTACK] = {0}; \
    unsigned long int i = 0; \
    const char fmt_str[] = "x%x:%d\n"; \
    for(i = 0; i < SIZEOFSTACK; i++) { \
        stack_space[i] = i % 255; \
    }   \
    bpf_printk("In tail call %s", #X);\
        bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + 0, stack_space[0]); \
    for(i = 0; i < SIZEOFSTACK; i++) { \
    }   \
    unsigned long x = bpf_get_stack_size(); \
    bpf_printk("testing_tail_func%s: bpf_get_stack_size helper %lx\n",#X ,x);\
    testing_bpf_to_bpf_calls ## X(ctx); \ 
    return 0; \
} \
struct { \
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY); \
	__uint(max_entries, 2); \
	__uint(key_size, sizeof(__u32)); \
	__array(values, int (void *)); \
} prog_array_init##X SEC(".maps") = { \
	.values = { \
		[1] = (void *)&testing_tail_func##X, \
	}, \
} \


static __attribute__((__noinline__)) int testing_b2b_last(void *ctx){
    /* SIZEOFSTACK bytes */
    unsigned char stack_space[48] = {0};

    /* 8 byte */
    unsigned long int i = 0;
    /* 8 byte */
    const char fmt_str[] = "x%x:%d\n";

    for(i = 0; i < 48; i++) {
        stack_space[i] = i % 255;
    }   

        bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + 0, stack_space[0]);
    for(i = 0; i < 48; i++) {
        //bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + i, stack_space[i]);
    }   
	
    
    unsigned long x = bpf_get_stack_size();

    bpf_printk("end testing bpf_get_stack_size helper %lx\n", x);
    return 0;

}

static __attribute__((__noinline__)) int testing_bpf_to_bpf_calls_final(void *ctx){
    /* SIZEOFSTACK bytes */
    unsigned char stack_space[SIZEOFSTACK] = {0};

    /* 8 byte */
    unsigned long int i = 0;
    /* 8 byte */
    const char fmt_str[] = "x%x:%d\n";

    for(i = 0; i < SIZEOFSTACK; i++) {
        stack_space[i] = i % 255;
    }   

        bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + 0, stack_space[0]);
    for(i = 0; i < SIZEOFSTACK; i++) {
        //bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + i, stack_space[i]);
    }   
	
    
    unsigned long x = bpf_get_stack_size();

    bpf_printk("end before testing bpf_get_stack_size helper %lx\n", x);
    //testing_b2b_last(ctx);
    return 0;

}

SEC("tracepoint/syscalls/sys_enter_execve")
int testing_tail_func29(void *ctx){
    /* SIZEOFSTACK bytes */
    unsigned char stack_space[SIZEOFSTACK] = {0};

    /* 8 byte */
    unsigned long int i = 0;
    /* 8 byte */
    const char fmt_str[] = "x%x:%d\n";

    for(i = 0; i < SIZEOFSTACK; i++) {
        stack_space[i] = i % 255;
    }   
    bpf_printk("in tail call 33");
        bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + 0, stack_space[0]);
    for(i = 0; i < SIZEOFSTACK; i++) {
    //    bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + i, stack_space[i]);
    }   
	
    unsigned long x = bpf_get_stack_size();

    bpf_printk("testing_tail_func29: bpf_get_stack_size helper %lx\n", x);
    //testing_bpf_to_bpf_calls_final(ctx);
    return 0;

}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 10);
	__uint(key_size, sizeof(__u32));
	__array(values, int (void *));
} prog_array_init29 SEC(".maps") = {
	.values = {
		[1] = (void *)&testing_tail_func29,
	},
};

//RTAIL_CALL(32, 33);
//RTAIL_CALL(31, 32);
//RTAIL_CALL(30, 31);
//RTAIL_CALL(29, 30);
RTAIL_CALL(28, 29);
RTAIL_CALL(27, 28);
RTAIL_CALL(26, 27);
RTAIL_CALL(25, 26);
RTAIL_CALL(24, 25);
RTAIL_CALL(23, 24);
RTAIL_CALL(22, 23);
RTAIL_CALL(21, 22);
RTAIL_CALL(20, 21);
RTAIL_CALL(19, 20);
RTAIL_CALL(18, 19);
RTAIL_CALL(17, 18);
RTAIL_CALL(16, 17);
RTAIL_CALL(15, 16);
RTAIL_CALL(14, 15);
RTAIL_CALL(13, 14);
RTAIL_CALL(12, 13);
RTAIL_CALL(11, 12);
RTAIL_CALL(10, 11);
RTAIL_CALL(9, 10);
RTAIL_CALL(8, 9);
RTAIL_CALL(7, 8);
RTAIL_CALL(6, 7);
RTAIL_CALL(5, 6);
RTAIL_CALL(4, 5);
RTAIL_CALL(3, 4);
RTAIL_CALL(2, 3);


static __attribute__((__noinline__)) int testing_bpf_to_bpf_calls(void *ctx){
    /* SIZEOFSTACK bytes */
    unsigned char stack_space[SIZEOFSTACK] = {0};

    /* 8 byte */
    unsigned long int i = 0;
    /* 8 byte */
    const char fmt_str[] = "x%x:%d\n";

    for(i = 0; i < SIZEOFSTACK; i++) {
        stack_space[i] = i % 255;
    }   

        bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + 0, stack_space[0]);
    for(i = 0; i < SIZEOFSTACK; i++) {
        //bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + i, stack_space[i]);
    }   
	
    bpf_tail_call(ctx, &prog_array_init2, 1);
    
    return 0;

}

SEC("tracepoint/syscalls/sys_enter_execve")
int testing_tail_func(void *ctx){
    /* SIZEOFSTACK bytes */
    unsigned char stack_space[SIZEOFSTACK] = {0};

    /* 8 byte */
    unsigned long int i = 0;
    /* 8 byte */
    const char fmt_str[] = "x%x:%d\n";

    for(i = 0; i < SIZEOFSTACK; i++) {
        stack_space[i] = i % 255;
    }   

        bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + 0, stack_space[0]);
    for(i = 0; i < SIZEOFSTACK; i++) {
        //bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + i, stack_space[i]);
    }   
	
    testing_bpf_to_bpf_calls(ctx); 
    //bpf_tail_call(ctx, &prog_array_init2, 1);
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

    /* SIZEOFSTACK bytes */
    unsigned char stack_space[SIZEOFSTACK] = {0};
   
    /* 8 byte */
    unsigned long int i = 0;
    /* 8 byte */
    const char fmt_str[] = "x%x:%d\n";
   
    for(i = 0; i < SIZEOFSTACK; i++) {
        stack_space[i] = i % 255;
    }   
   
        bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + 0, stack_space[0]);
    for(i = 0; i < SIZEOFSTACK; i++) {
        //bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + i, stack_space[i]);
    }  


    
    bpf_printk("testing bpf tail call functions");

    bpf_tail_call(ctx, &prog_array_init, 1);


    return 0;

}


char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;



