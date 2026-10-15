# eBPF-proxy

`tunnel-relay-4-vm.sh` sets up a four-node Geneve overlay across four virtual
machines (VS1–VS4).  It creates a `geneve0` interface on the local VM, adds
static ARP entries so packets can traverse the tunnel without broadcasting, and
attaches an eBPF TC filter (via `user_control`) that rewrites Geneve headers on
the fly to relay traffic hop-by-hop through the chain VS1 → VS2 → VS3 → VS4.
Once the overlay is live it prints ready-to-run commands for the TLS proxy
(`proxy`) and a lightweight HTTP backend, then tears everything down on exit.

## Further reading

- [4VM-TEST.md](eBPF-proxy/4VM-TEST.md) – step-by-step test procedure for the four-VM topology
- [EBPF.md](eBPF-proxy/EBPF.md) – explanation of the eBPF TC program and `user_control` design
