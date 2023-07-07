// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018 Facebook

#include <stdio.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/filter.h>

#include <bpf/bpf.h>

#include "cgroup_helpers.h"
#include <bpf/bpf_endian.h>
#include "bpf_util.h"

#define CG_PATH		"/foo"
#define MAX_INSNS	512

char bpf_log_buf[BPF_LOG_BUF_SIZE];
static bool verbose = false;

struct sock_test {
	const char *descr;
	/* BPF prog properties */
	struct bpf_insn	insns[MAX_INSNS];
	enum bpf_attach_type expected_attach_type;
	enum bpf_attach_type attach_type;
	/* Socket properties */
	int domain;
	int type;
	/* Endpoint to bind() to */
	const char *ip;
	unsigned short port;
	unsigned short port_retry;
	/* Expected test result */
	enum {
		LOAD_REJECT,
		ATTACH_REJECT,
		BIND_REJECT,
		SUCCESS,
		RETRY_SUCCESS,
		RETRY_REJECT
	} result;
};

static struct sock_test tests[] = {
	{
		.descr = "hello_kern load",
		.insns = {
			// BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
			// BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6,
			// 	    offsetof(struct bpf_sock, src_ip6[0])),
			// BPF_MOV64_IMM(BPF_REG_0, 1),
			// BPF_EXIT_INSN(),
		},
		.expected_attach_type = BPF_TRACE_FENTRY,
		.attach_type = BPF_TRACE_FENTRY,
		.result = LOAD_REJECT,
	},
};

static size_t probe_prog_length(const struct bpf_insn *fp)
{
	size_t len;

	for (len = MAX_INSNS - 1; len > 0; --len)
		if (fp[len].code != 0 || fp[len].imm != 0)
			break;
	return len + 1;
}

static int load_sock_prog(const struct bpf_insn *prog,
			  enum bpf_attach_type attach_type)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts);
	int ret, insn_cnt;

	insn_cnt = probe_prog_length(prog);

	opts.expected_attach_type = attach_type;
	opts.log_buf = bpf_log_buf;
	opts.log_size = BPF_LOG_BUF_SIZE;
	opts.log_level = 2;

	ret = bpf_prog_load(BPF_PROG_TYPE_TRACING, "hello_kern", "GPL", prog, insn_cnt, &opts);
	if (verbose && ret < 0)
		fprintf(stderr, "%s\n", bpf_log_buf);

	return ret;
}

static int attach_sock_prog(int cgfd, int progfd,
			    enum bpf_attach_type attach_type)
{
	return bpf_prog_attach(progfd, cgfd, attach_type, BPF_F_ALLOW_OVERRIDE);
}

static int run_test_case(int cgfd, const struct sock_test *test)
{
	int progfd = -1;
	int err = 0;

	printf("Test case: %s .. ", test->descr);
	progfd = load_sock_prog(test->insns, test->expected_attach_type);
	if (progfd < 0) {
		if (test->result == LOAD_REJECT)
			goto out;
		else
			goto err;
	}

	if (attach_sock_prog(cgfd, progfd, test->attach_type) < 0) {
		if (test->result == ATTACH_REJECT)
			goto out;
		else
			goto err;
	}

	sleep(0.5);

err:
	err = -1;
out:
	/* Detaching w/o checking return code: best effort attempt. */
	if (progfd != -1)
		bpf_prog_detach(cgfd, test->attach_type);
	close(progfd);
	printf("[%s]\n", err ? "FAIL" : "PASS");
	return err;
}

static int run_tests(int cgfd)
{
	int passes = 0;
	int fails = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(tests); ++i) {
		if (run_test_case(cgfd, &tests[i]))
			++fails;
		else
			++passes;
	}
	printf("Summary: %d PASSED, %d FAILED\n", passes, fails);
	return fails ? -1 : 0;
}

int main(int argc, char **argv)
{
	int cgfd = -1;
	int err = 0;

	cgfd = cgroup_setup_and_join(CG_PATH);
	if (cgfd < 0)
		goto err;

	/* Use libbpf 1.0 API mode */
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	if (run_tests(cgfd))
		goto err;

	goto out;
err:
	err = -1;
out:
	close(cgfd);
	cleanup_cgroup_environment();
	return err;
}
