/*
 * Tests the bpf hello program
 */

#define _GNU_SOURCE

#include <stddef.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <error.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#define OUTPUT_SIZE 100
#define TRACE_PIPE_PATH "/sys/kernel/debug/tracing/trace_pipe"

void* read_trace_pipe_output(void* buf){
    //init vars
	int c, buf_index;

    //create char* reference to void* buf
    char* buffer = (char*)buf;

    //open file
	FILE* f = fopen(TRACE_PIPE_PATH, "r");

    //loop through each char in file
	while(buf_index < OUTPUT_SIZE) {
		c = fgetc(f);
		if(feof(f)) //stop if end of file
			break;
		*(buffer + buf_index) = c; //append to the char* buf
		buf_index++;
	}

	fclose(f);
    return NULL;
}

static int do_main(void)
{
    //initialize vars
	char buf[OUTPUT_SIZE];
	pthread_t output_thread;

    //create thread
	if(pthread_create(&output_thread, NULL, (void*)read_trace_pipe_output, (void*)buf) < 0){
		error(1, 0, "pthread_create() failed");
	}
	
    //let thread start reading
    sleep(0.5);

    //trigger bpf prog with syscall
	getpid();

    //read in output
    pthread_join(output_thread, NULL);
    printf("This is the output: %s\n", buf);

	return 0;
}


int main(int argc, char **argv)
{
	return do_main();
}
