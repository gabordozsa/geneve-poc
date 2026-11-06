# Printing information about ingress/egress eBPF filters with `tc`

Use `tc filter show` on the interface and direction. Replace `<iface>` with your interface name.

```bash
# Filters on ingress / egress
sudo tc filter show dev <iface> ingress
sudo tc filter show dev <iface> egress

# Same, with the program's instructions/details
sudo tc -s filter show dev <iface> ingress    # -s adds statistics
sudo tc -d filter show dev <iface> egress     # -d adds details

# JSON output
sudo tc -j -p filter show dev <iface> ingress

# Show the clsact qdisc that the filters hang off
sudo tc qdisc show dev <iface>
```

For the filters from `geneve-nat/user_control`, the output looks like this (taken from a test run):

```
filter protocol all pref 1 bpf chain 0 handle 0x1 udp_port_save:[2232] direct-action not_in_hw id 2232 name udp_port_save tag 155f50a2a4471809 jited
```

- `pref 1`: the priority we attached with.
- `udp_port_save`: the program name.
- `direct-action`: the return codes (`TC_ACT_OK`, `TC_ACT_SHOT`) are used directly.
- `id 2232`: the kernel BPF program ID.
- `jited`: the program is JIT-compiled.

## More details with `bpftool`

Use the `id` from the `tc` output:

```bash
sudo bpftool net show dev <iface>        # tc programs attached to the iface
sudo bpftool prog show id <id>           # program info and referenced map IDs
sudo bpftool prog dump xlated id <id>    # eBPF instructions
sudo bpftool map dump name port_map      # saved port; key 6081 (0x17c1)
```

## Removing filters by hand

If the program was killed without cleaning up:

```bash
sudo tc filter del dev <iface> ingress
sudo tc filter del dev <iface> egress
# or remove everything, including clsact:
sudo tc qdisc del dev <iface> clsact
```

List all loaded (geneve) eBPF:

```bash
sudo bpftool prog show | grep geneve
```

Check all namespaces (when 'ip netns ls' shows nothing)

```bash
sudo lsns -t net
```

Delete stuck namespace:

```bash
sudo kill <PID>
```

## Note

The `bpf_printk()` output is not shown by `tc`. Read it with:

```bash
sudo cat /sys/kernel/tracing/trace  # [trace_pipe]
```

## Understanding `tc qdisc show dev <iface>` output

Example output:

```
$ tc qdisc show dev ens3
qdisc mq 0: root 
qdisc pfifo_fast 0: parent :3 bands 3 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1
qdisc pfifo_fast 0: parent :2 bands 3 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1
qdisc pfifo_fast 0: parent :1 bands 3 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1
```

### Breakdown

1. **`qdisc mq 0: root`**
   - **`mq` (Multi-Queue):** Indicates that the interface has multiple independent hardware/driver transmit (TX) queues (e.g., multi-queue NIC / virtio-net).
   - **`root`:** `mq` is the root queueing discipline attached directly to the interface, managing and attaching a sub-qdisc to each TX queue.
   - In this example, there are **3 TX queues** (represented as parents `:1`, `:2`, and `:3`).

2. **`qdisc pfifo_fast 0: parent :1 / :2 / :3 ...`**
   - **`pfifo_fast` (Packet FIFO Fast):** The default Linux leaf qdisc handling transmission on each individual queue.
   - **`parent :1`, `parent :2`, `parent :3`:** Identifies which TX queue instance this qdisc belongs to.
   - **`bands 3`:** Each queue maintains 3 internal priority bands:
     - **Band 0:** Highest priority (emptied first).
     - **Band 1:** Normal priority (emptied if Band 0 is empty).
     - **Band 2:** Lowest priority / bulk traffic (emptied if Bands 0 and 1 are empty).
   - **`priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1`:**
     - A 16-element lookup table mapping IP **Type of Service (TOS)** / priority bits (0–15) to one of the 3 priority bands (0, 1, or 2).
