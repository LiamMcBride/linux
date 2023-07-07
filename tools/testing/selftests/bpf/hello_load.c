#include <error.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "hello_load.h"

const char *cfg_pin_path = "/sys/fs/bpf/hello_kern";
bool cfg_attach = true;
char *cfg_prog_name;
char *cfg_path_name;

static void load_and_attach_program(void){
    int prog_fd, ret;
    struct bpf_object *obj;

	char cwd[256];
	cfg_prog_name = "trace_enter_execve";
	// cfg_path_name = "/linux/fs/bpf/hello_kern";
	cfg_path_name = "/linux/samples/bpf/hello_kern.o";
	getcwd(cwd, sizeof(cwd));
	printf("CWD: %s\n", cwd);
	printf("prog: %s\n", cfg_prog_name);
	printf("path: %s\n", cfg_path_name);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	ret = bpf_hello_load(&obj, cfg_path_name, cfg_prog_name,
			    &prog_fd);
	printf("Loaded\n");
	if (ret)
		error(1, 0, "error: bpf_hello_load %s", cfg_path_name);
	
	struct bpf_program* prog = bpf_object__find_program_by_name(obj, cfg_prog_name);

    // ret = bpf_prog_attach(prog_fd, 0, BPF_TRACE_FENTRY, 0);
    // ret = bpf_prog_attach(prog_fd, 0, BPF_TRACE_RAW_TP, 0);
	bpf_program__attach(prog);
	printf("Attached\n");
    // if (ret)
    //     error(1, 0, "error: bpf_prog_attach %s", cfg_path_name);
	

    ret = bpf_object__pin(obj, cfg_pin_path);
	printf("Pinned\n");
    if (ret)
        error(1, 0, "error: bpf_object__pin %s", cfg_pin_path);
	
}

static void detach_program(void){
    char command[64];
    int ret;

    ret = bpf_prog_detach(0, BPF_TRACE_FENTRY);
    if (ret)
        error(1, 0, "bpf_prog_detach");
    sprintf(command, "rm -r %s", cfg_pin_path);
    ret = system(command);
    if (ret)
        error(1, errno, "%s", command);
}

static void parse_opts(int argc, char **argv)
{
	bool attach = false;
	bool detach = false;
	int c;

	while ((c = getopt(argc, argv, "adp:s:")) != -1) {
		switch (c) {
		case 'a':
			if (detach)
				error(1, 0, "attach/detach are exclusive");
			attach = true;
			break;
		case 'd':
			if (attach)
				error(1, 0, "attach/detach are exclusive");
			detach = true;
			break;
		case 'p':
			if (cfg_path_name)
				error(1, 0, "only one path can be given");

			cfg_path_name = optarg;
			break;
		case 's':
			if (cfg_prog_name)
				error(1, 0, "only one prog can be given");

			cfg_prog_name = optarg;
			break;
		}
	}

	if (detach)
		cfg_attach = false;

	if (cfg_attach && !cfg_path_name)
		error(1, 0, "must provide a path to the BPF program");

	if (cfg_attach && !cfg_prog_name)
		error(1, 0, "must provide a section name");
}

int main(int argc, char **argv){
    parse_opts(argc, argv);
    if (cfg_attach)
        load_and_attach_program();
    else
        detach_program();
    return 0;
}