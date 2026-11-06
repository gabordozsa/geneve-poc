#! /usr/bin/env bash

# Ubuntu specific incdir ?
INCDIR="-I/usr/include/$(uname -m)-linux-gnu"

clang -O2 -g -target bpf $INCDIR -c udp-port-rewrite.c -o udp-port-rewrite.o
gcc -O2 user_control.c -o user_control -lbpf -lelf
