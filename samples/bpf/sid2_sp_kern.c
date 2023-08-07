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



SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(void *ctx){

    bpf_printk("Inside the kernel function\n");
    
    int x = bpf_get_stack_size();

    bpf_printk("testing bpf_get_stack_size helper %d", x);
    
    return 0;

}


char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;



