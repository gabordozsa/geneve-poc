#! /usr/bin/env bash

clang -O2 -g -target bpf -c udp-port-rewrite.c -o udp-port-rewrite.o
gcc -O2 user_control.c -o user_control -lbpf -lelf
