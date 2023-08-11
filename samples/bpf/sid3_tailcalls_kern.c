#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

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

static __attribute__((__noinline__)) int testing_bpf_to_bpf_calls5(void *ctx){
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
	
//    int sp;
//    bpf_printk("end stackpointer: %x\n", &sp);
//    bpf_tail_call(ctx, &prog_array_init3, 1);
    
    return 0;

}

SEC("tracepoint/syscalls/sys_enter_execve")
int testing_tail_func5(void *ctx){
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
	
    testing_bpf_to_bpf_calls5(ctx); 
    return 0;

}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 10);
	__uint(key_size, sizeof(__u32));
	__array(values, int (void *));
} prog_array_init5 SEC(".maps") = {
	.values = {
		[1] = (void *)&testing_tail_func5,
	},
};

static __attribute__((__noinline__)) int testing_bpf_to_bpf_calls4(void *ctx){
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
	
//    int sp;
//    bpf_printk("end stackpointer: %x\n", &sp);
    bpf_tail_call(ctx, &prog_array_init5, 1);
    
    return 0;

}

SEC("tracepoint/syscalls/sys_enter_execve")
int testing_tail_func4(void *ctx){
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
	
    testing_bpf_to_bpf_calls4(ctx); 
    return 0;

}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 10);
	__uint(key_size, sizeof(__u32));
	__array(values, int (void *));
} prog_array_init4 SEC(".maps") = {
	.values = {
		[1] = (void *)&testing_tail_func4,
	},
};


static __attribute__((__noinline__)) int testing_bpf_to_bpf_calls3(void *ctx){
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
	
//    int sp;
//    bpf_printk("end stackpointer: %x\n", &sp);
    bpf_tail_call(ctx, &prog_array_init4, 1);
    
    return 0;

}

SEC("tracepoint/syscalls/sys_enter_execve")
int testing_tail_func3(void *ctx){
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
	
    testing_bpf_to_bpf_calls3(ctx); 
    return 0;

}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 10);
	__uint(key_size, sizeof(__u32));
	__array(values, int (void *));
} prog_array_init3 SEC(".maps") = {
	.values = {
		[1] = (void *)&testing_tail_func3,
	},
};

static __attribute__((__noinline__)) int testing_bpf_to_bpf_calls2(void *ctx){
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
	
    bpf_tail_call(ctx, &prog_array_init3, 1);
    
    return 0;

}

SEC("tracepoint/syscalls/sys_enter_execve")
int testing_tail_func2(void *ctx){
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

    for(i = 0; i < SIZEOFSTACK; i++) {
        bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + i, stack_space[i]);
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
    
    int sp;
    bpf_printk("start stackpointer: %x\n", &sp);

    bpf_printk("testing bpf_get_stack_size helper\n");

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
        if(i==0){
            bpf_printk("----------->");
        }
        bpf_trace_printk(fmt_str, sizeof(fmt_str), stack_space + i, stack_space[i]);
    }  


    
    bpf_printk("testing bpf tail call functions");

    bpf_tail_call(ctx, &prog_array_init, 1);


    return 0;

}


char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;



