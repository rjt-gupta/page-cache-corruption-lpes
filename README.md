# Page Cache Corruption LPEs

**3 Linux kernel local privilege escalation exploits. Same bug class as Dirty COW and Dirty Pipe. Root shell in seconds. Every major distro affected.**

All three corrupt the kernel's page cache — the in-memory copy of files that processes actually read and execute. The on-disk file is never touched. File integrity tools see nothing. `execve("/usr/bin/su")` loads from cache → runs your shellcode → root.

---

## The Exploits

| Exploit | CVE | Mechanism | Time to Root | Lines |
|---------|-----|-----------|:------------:|:-----:|
| [**Dirty Pedit**](dirty_pedit/) | CVE-2026-46331 | TC pedit COW gap (u32 wraparound) | **< 1 second** | 275 |
| [**skb_shift**](skb_shift/) | CVE-2026-43503 | TCP SACK frag transfer flag loss | ~10 seconds | 500 |
| [**GRO Flag Loss**](gro/) | CVE-2026-43503 | GRO coalesce frag transfer flag loss | ~10 seconds | 550 |

All three: unprivileged → root. No special permissions. User namespaces only.

---

## What's the Bug Class?

Every exploit in this repo follows the same pattern:

```
1. Get page-cache pages into a kernel buffer (splice)
2. Bypass the copy-on-write defense
3. Write in-place → read-only file corrupted in memory
```

What differs is HOW the defense is bypassed and WHAT performs the write:

| Exploit | Defense Bypassed | Writer |
|---------|-----------------|--------|
| Dirty Pedit | `skb_ensure_writable` (u32 wraparound → partial COW) | `skb_store_bits` (direct 4-byte write) |
| skb_shift | `SKBFL_SHARED_FRAG` flag lost during TCP SACK | ESP AES-GCM decrypt (1 byte per packet) |
| GRO Flag Loss | `SKBFL_SHARED_FRAG` flag lost during GRO merge | ESP AES-GCM decrypt (1 byte per packet) |

---

## The Lineage

```
2016  Dirty COW         COW race via mmap + fork
2022  Dirty Pipe        Stale PIPE_BUF_FLAG_CAN_MERGE in splice
2026  Copy Fail         AF_ALG in-place AEAD on page-cache scatterlist
2026  Dirty Frag        ESP skip_cow on splice'd frags (missing flag)
2026  Fragnesia         skb_try_coalesce drops SHARED_FRAG flag
2026  Dirty Pedit  ←    TC pedit COW gap, no crypto needed
2026  skb_shift    ←    TCP SACK drops SHARED_FRAG, ESP writes
2026  GRO Flag Loss ←   GRO merge drops SHARED_FRAG, ESP writes
```

---

## Affected Versions

| Exploit | Introduced | Fixed | Affected Distros |
|---------|-----------|-------|-----------------|
| Dirty Pedit | v5.18 (May 2022) | v7.1-rc7 | Ubuntu, RHEL, Debian, Fedora, SUSE |
| skb_shift | v3.9 (2013) | v7.1-rc5 | Every distro for 13 years |
| GRO Flag Loss | v3.9 (2013) | v7.1-rc5 | Every distro for 13 years |

Default configs. No hardening needed to be vulnerable. If you run Linux, you were affected.

---

## Why Dirty Pedit is Different

skb_shift and GRO both use the same exploitation technique: lose the `SKBFL_SHARED_FRAG` flag, then let ESP crypto XOR into page-cache pages one byte at a time using a precomputed IV lookup table.

Dirty Pedit is a completely different beast:
- **No crypto.** No XFRM, no ESP, no AES-GCM, no IV tables.
- **Direct write.** TC pedit writes exactly the bytes you specify via `skb_store_bits`.
- **Sub-second.** One packet = 12 bytes written. Root in one shot.
- **Different defense bypass.** Doesn't touch SHARED_FRAG at all — breaks `skb_ensure_writable` through integer wraparound.

---

## Build

```bash
# Build all three
cd dirty_pedit && gcc -static -O2 -o exploit exploit.c && cd ..
cd skb_shift   && gcc -static -O2 -o exploit exploit.c && cd ..
cd gro         && gcc -static -O2 -o exploit exploit.c && cd ..
```

Each exploit is a single self-contained C file. No dependencies beyond libc.

---

## Run

```bash
# Any of the three (as unprivileged user):
./exploit
# → root shell
```

Requires: Linux kernel in affected version range + `CONFIG_USER_NS=y` (default on all major distros).

---

## Output (Dirty Pedit)

```
[*] Dirty Pedit — Local Privilege Escalation
[*] uid=1000 pid=42
[*] Victim line at offset 186: nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
[*] Injecting user 'a' (uid=0, no password) over victim line...
[+] User 'a' injected with uid=0!
[+] Running: su a
# id
uid=0(root) gid=0(root) groups=0(root)
```

## Output (skb_shift / GRO)

```
[*] uid=1000 euid=1000
[*] IV table pre-computed (256 entries)
[*] Writing 192 bytes to /usr/bin/su...
  [120] 0x00→0x48 ... OK
  [121] 0x00→0x31 ... OK
[*] Write complete: 192/192
[!] /usr/bin/su page cache overwritten!
# whoami
root
```

---

## Key Properties

| Property | Dirty Pedit | skb_shift | GRO |
|----------|:-----------:|:---------:|:---:|
| Privileges | None (userns) | None (userns) | None (userns) |
| File access | O_RDONLY | O_RDONLY | O_RDONLY |
| Crypto needed | No | Yes (AES-GCM) | Yes (AES-GCM) |
| Write control | 4 bytes/packet | 1 byte/packet | 1 byte/packet |
| Reliability | Deterministic | Deterministic | Probabilistic (retry) |
| K8s container escape | No (no veth needed) | No | **Yes** (veth+GRO default) |
| Attack surface | geneve + TC | loopback + espintcp | veth + ESP-in-UDP |

---

## Responsible Disclosure

All vulnerabilities were responsibly disclosed to the Linux kernel security team and networking maintainers. Patches are merged upstream and backported to stable trees.

- CVE-2026-46331: Fixed in v7.1-rc7, commit `899ee91156e5`
- CVE-2026-43503: Fixed in v7.1-rc5, commit `48f6a5356a33`

These exploits are published for educational and defensive purposes after patches were available. Page-cache corruption is memory-only — reboot or `echo 1 > /proc/sys/vm/drop_caches` restores original files.

---

## Author

**Rajat Gupta** — Offensive Security @ Qualcomm

---

## License

MIT
