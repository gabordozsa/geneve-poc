#!/bin/env bash

tc qdisc add dev gen0 clsact
tc filter add dev gen0 ingress bpf da obj geneve_parser.o sec classifier
