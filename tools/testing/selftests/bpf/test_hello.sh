#!/bin/bash

BPF_FILE="hello_kern.o"
DIR="../../../samples/bpf"

export TESTNAME=test_hello
unmount=0

FILE="$DIR/$BPF_FILE"

./hello_load -p $FILE -s _dissect

./test_hello

exit 0