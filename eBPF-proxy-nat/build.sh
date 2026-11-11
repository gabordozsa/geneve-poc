EBPF_SRC=geneve_relay_nat.c
CTRL_SRC=user_control.c

# Ubuntu specific incdir ?
INCDIR="-I/usr/include/$(uname -m)-linux-gnu"

echo "*** Compile eBPF"
clang -O2  $INCDIR -g -target bpf -c $EBPF_SRC -o ${EBPF_SRC%.c}.o

echo "*** Build user control plane part"
gcc -O2 $CTRL_SRC -o ${CTRL_SRC%.c} -lbpf -lelf
