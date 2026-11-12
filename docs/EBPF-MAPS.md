# Updating eBPF Map Values In Place

**Question:** `bpf_map_lookup_elem()` returns a pointer to a value. Can the value in the map be updated in place via that pointer?

**Answer:** Yes. In eBPF, `bpf_map_lookup_elem()` returns a pointer directly into the map's value storage, not a copy, for most map types. Writing through that pointer updates the map entry in place. For example:

```c
struct stats *s = bpf_map_lookup_elem(&stats_map, &key);
if (s) {
    s->pkts++;          // plain, non-atomic in-place update
    s->bytes += len;
}
```

## Caveats

1. **Always NULL-check.** The verifier requires it before you dereference the pointer.

2. **Races.** Several CPUs can run your program at once, and plain writes aren't atomic across them.
   - Use `__sync_fetch_and_add(&s->pkts, 1)` for atomic counters. It works on 32-bit and 64-bit fields.
   - Use `bpf_spin_lock` if you need to update several fields consistently. The map value needs a `struct bpf_spin_lock` field and BTF. Spin locks are supported on hash, array and cgroup-storage maps, but not in tracing programs.
   - Use per-CPU maps (`BPF_MAP_TYPE_PERCPU_ARRAY` and `BPF_MAP_TYPE_PERCPU_HASH`) to avoid contention. Each CPU gets its own copy of the value, and the pointer you get refers to the current CPU's copy. Userspace then has to aggregate across CPUs.

3. **Pointer lifetime.** The pointer is only valid for the current program invocation. Don't assume it stays valid after you delete the element. A concurrent `bpf_map_delete_elem` (or LRU eviction) can free the entry, though RCU protection keeps the memory valid during the program run. Don't cache the pointer across invocations.

4. **Which maps allow it.** In-place writes work for array, hash, LRU hash, per-CPU variants and similar maps. Some map types have restrictions. Maps loaded with `BPF_F_RDONLY_PROG`, or `.rodata` maps, are read-only to the program. Map-in-map and some special types (e.g. sockmap, devmap) return different kinds of values that aren't plain data.

5. **Userspace visibility.** Userspace reads through `bpf_map_lookup_elem()` on the fd, which copies the value out. It will see your in-place updates, but possibly mid-update if you aren't using atomics or a lock.

6. **No need to call `bpf_map_update_elem()`.** It's only needed to insert new keys or replace a whole value. Calling it for an existing hash key from the program works but is slower and can race with in-place writes.
