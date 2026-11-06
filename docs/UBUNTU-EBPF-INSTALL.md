# Installing Clang for eBPF on Ubuntu

## Required Packages

```bash
sudo apt update
sudo apt install -y clang llvm libelf-dev linux-headers-$(uname -r)
```

| Package | Purpose |
|---|---|
| `clang` | C compiler that can emit BPF bytecode (`-target bpf`) |
| `llvm` | Backend used by Clang to generate BPF ELF objects |
| `libelf-dev` | Required for reading/writing ELF files (used by loaders like `libbpf`) |
| `linux-headers-$(uname -r)` | Kernel headers needed to compile against kernel data structures |

## Optional but Commonly Needed

```bash
# libbpf development headers (preferred modern BPF library)
sudo apt install -y libbpf-dev

# bpftool — inspect/load BPF programs, generate skeleton headers
sudo apt install -y linux-tools-$(uname -r) linux-tools-generic

# For older kernels or iproute2-based loading (tc/ip)
sudo apt install -y iproute2
```

## Verify the Install

```bash
clang --version
llc --version        # should show BPF as a registered target
```

To confirm BPF is a supported target in your LLVM:

```bash
llc --version | grep bpf
```

You should see output like `bpf    - BPF (host endian)` and `bpfeb` / `bpfel`.

## Typical Compile Command

```bash
clang -O2 -g -target bpf -c your_prog.bpf.c -o your_prog.o
```
