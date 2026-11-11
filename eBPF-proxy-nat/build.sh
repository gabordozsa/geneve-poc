EBPF_SRC=geneve_relay_nat.c
CTRL_SRC=user_control.c

echo "*** Compile eBPF"
clang -O2 -g -target bpf -c $EBPF_SRC -o ${EBPF_SRC%.c}.o

echo "*** Build user control plane part"
gcc -O2 $CTRL_SRC -o ${CTRL_SRC%.c} -lbpf -lelf
