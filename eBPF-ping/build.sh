EBPF_SRC=redirect_map.c
CTRL_SRC=user_control.c

echo "*** Compile eBPF"
echo clang -O2 -g -target bpf -c $EBPF_SRC -o ${EBPF_SRC%.c}.o

echo "*** Build user control plane part"
echo gcc -O2 $CTRL_SRC -o ${CTRL_SRC%.c} -lbpf -lelf
