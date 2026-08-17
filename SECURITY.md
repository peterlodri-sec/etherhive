# etherhive — Security Architecture

## Zero-Disk. Zero-Trace. Self-Encrypted Memory.

> The chat lives only in encrypted memory regions. Nothing touches disk.
> Per-byte encryption seeded by a quantized LLM + CSPRNG nonce via HKDF.
> Multihop SSH bootstrap via /dev/fd pipes (never touches filesystem).
> When the process dies, the data dies with it.

---

## What's actually running vs. what's designed here

This document is a **design doc**, not a description of the running
binaries -- an external review ([#1](https://github.com/peterlodri-sec/etherhive/issues/1))
found that most of it was being read as the latter. Layer by layer:

| Layer | Live in `etherhive-ircd` / `etherhive-client` today? |
|-------|-------------------------------------------------------|
| Layer -2 (SSH multihop init) | No -- design only, no code path calls this |
| Layer -1 (memfd/mlock/sealed memory) | No -- `src/memory.rs` exists and has tests, but nothing in `main.rs`/`ircd.rs`/`client.rs` calls it. Chat lives in an ordinary `HashMap`/`Vec`/`Mutex`. |
| Layer 0 (`etherhive-vpn`, Mullvad) | No -- `etherhive-vpn` prints `[OK] tunnel established (simulated)` and exits |
| Layer 1 (`etherhive-crypt`, per-byte LLM sub-keys) | No -- `etherhive-crypt` doesn't wrap traffic; `src/seed.rs`'s cipher is unauthenticated XOR with no nonce, not the HKDF+CSPRNG scheme documented below |
| Layer 2 (`etherhive-mesh`, Tailscale/Headscale) | No -- `etherhive-mesh` prints `[OK] mesh joined (simulated)` and exits |
| Layer 3 (`etherhive-ircd`, transport) | **Yes**, but as X25519 + ChaCha20Poly1305 directly (not "encrypted per-byte, stored in sealed memory" as stated below) -- see `src/crypto.rs`. Had a real nonce-reuse bug, fixed in [#2](https://github.com/peterlodri-sec/etherhive/pull/2). |
| 1:1 E2E (not a layer below, but the one that's real) | **Yes** -- `/dm` in the TUI client runs X3DH + Double Ratchet + ML-KEM-1024 hybrid (`src/ratchet.rs`). This is the one part of the crypto story that matches its claims. |

If you're evaluating whether to trust this for something sensitive: trust
the transport layer and `/dm`, and nothing else on this page yet.

---

## Layer -2: Multihop SSH Throwaway Init (RAM-only)

Before any sidecar starts, the connection is bootstrapped through
a chain of throwaway SSH hops using /dev/fd pipes — keys never touch disk:

```
etherhive init
  │
  ▼
# Generate Ed25519 keys directly into RAM pipes (NOT /tmp)
mkfifo /dev/shm/etherhive-hop-1.sk
ssh-keygen -t ed25519 -f /dev/fd/3 -N "" 3>/dev/shm/etherhive-hop-1.sk &
mkfifo /dev/shm/etherhive-hop-2.sk
ssh-keygen -t ed25519 -f /dev/fd/4 -N "" 4>/dev/shm/etherhive-hop-2.sk &
mkfifo /dev/shm/etherhive-hop-3.sk
ssh-keygen -t ed25519 -f /dev/fd/5 -N "" 5>/dev/shm/etherhive-hop-3.sk &
  │
  ▼
ssh -i /dev/fd/3 user@hop1.example.com \
  ssh -i /dev/fd/4 user@hop2.example.com \
    ssh -i /dev/fd/5 user@hop3.example.com \
      "exec etherhive up --no-init"
  │
  ▼
# Named pipes in /dev/shm are tmpfs — gone on reboot/unlink
rm -f /dev/shm/etherhive-hop-*.sk
```

Properties:
- SSH keys exist only as named pipes in tmpfs (RAM-backed, never on SSD)
- No shred needed — tmpfs is volatile memory
- The final hop spawns the etherhive sidecars directly
- No SSH key material persists on any storage device
- If any hop is compromised, the attacker sees only another SSH connection

---

## Layer -1: Self-Encrypted Memory (memfd + mlock + anti-forensics)

All chat data lives in a memory-only filesystem backed by an encrypted `memfd`:

```rust
use std::fs::File;
use std::os::unix::io::FromRawFd;

// 0. Disable ptrace inspection and core dumps (anti-forensics)
unsafe {
    libc::prctl(libc::PR_SET_DUMPABLE, 0);

    // Disable coredumps
    let mut rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    libc::setrlimit(libc::RLIMIT_CORE, &rlim);
}

// 1. Create anonymous in-memory file (never touches disk)
let fd = unsafe { libc::memfd_create(
    b"etherhive-chat\0".as_ptr() as *const _,
    libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING
) };

// 2. Set size
unsafe { libc::ftruncate(fd, size as libc::off_t); }

// 3. Map into memory with read+write
let ptr = unsafe {
    libc::mmap(
        std::ptr::null_mut(), size,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED, fd, 0,
    )
};

// 4. Write data / initialize buffers HERE (while still writable)

// 5. Lock into RAM + exclude from core dumps
unsafe {
    libc::mlock(ptr, size);
    libc::madvise(ptr, size, libc::MADV_DONTDUMP);
}

// 6. Seal — no resize, no write access after population
// NOTE: crypto.mem keeps write access for session key rotation
unsafe {
    libc::fcntl(fd, libc::F_ADD_SEALS,
        libc::F_SEAL_SHRINK |   // cannot decrease size
        libc::F_SEAL_GROW |     // cannot increase size
        libc::F_SEAL_WRITE |    // cannot write to it (for chat/identity/seed)
        libc::F_SEAL_SEAL       // no further seals can be added
    );
}

// 7. Make read-only
unsafe { libc::mprotect(ptr as *mut libc::c_void, size, libc::PROT_READ); }
```

### Memory regions and sealing policies:

| Region | Write after init? | Reason |
|--------|-------------------|--------|
| `chat.mem` | NO (F_SEAL_WRITE) | Message history is append-only, sealed |
| `crypto.mem` | YES (no F_SEAL_WRITE) | Session keys rotate every N messages |
| `identity.mem` | NO (F_SEAL_WRITE) | Honesty vector loaded once, immutable |
| `seed.mem` | NO (F_SEAL_WRITE) | LLM weights loaded once, immutable |

### Required capabilities:

```bash
# mlock of >64KB requires CAP_IPC_LOCK
sudo setcap cap_ipc_lock=+ep /usr/bin/etherhive
```

---

## Layer 0: etherhive-vpn (Mullvad Double Hop)

```
etherhive-vpn --entry switzerland --exit iceland
```

Two-hop WireGuard tunnel. Rotated every 4 hours.

---

## Layer 1: etherhive-crypt (Kyber + X25519 + Per-Byte LLM Sub-Keys)

### Hybrid Key Exchange

Kyber-1024 (ML-KEM) + X25519 ECDH. Shared secret = Kyber || X25519.

### Forward Secrecy via Session Key Rotation

```
Every N=1000 messages: rotate session key.
  1. Fresh Kyber+X25519 exchange
  2. New session_key = HKDF(new_shared, "etherhive-rotate")
  3. Nonce counter resets
  4. Old sub-keys undecryptable: need old nonce + old session_key + old LLM weights
```

### Per-Byte Sub-Key Derivation (Timing-Safe)

```
For byte i in message:
  // Load ALL THREE possible sub-keys into registers (no timing leak)
  sub_key_neg[i]  = HKDF(session_key || "neg" || nonce || i)
  sub_key_zero[i] = HKDF(session_key || "zero" || nonce || i)
  sub_key_pos[i]  = HKDF(session_key || "pos" || nonce || i)

  // Use constant-time selection (cmov / select) based on LLM weight
  w = LLM_weights[i % weight_count]  // {-1, 0, +1}
  sub_key[i] = select(sub_key_neg, sub_key_zero, sub_key_pos, w)

  cipher_byte[i] = plain_byte[i] XOR sub_key[i][0]
```

This prevents cache-timing attacks on the weight lookup: all three
sub-keys are always loaded, the selection is constant-time.

### LLM Weight Distribution (Out-of-Band)

The LLM checkpoint is NOT transmitted over the encrypted channel.
Distribution options:

1. **BIP39 seed phrase**: 12 words → HKDF → deterministic weights.
   Both peers agree on 12 words. No file transfer needed.
2. **QR-split**: weights split across N QR codes, scanned in sequence
3. **USB dead drop**: physical handoff
4. **Pre-shared in hardware**: burned into ROM/flash at manufacture

### LLM Weights + CSPRNG via HKDF (Not Raw XOR)

LLM weights are NOT used directly as keystream. They are combined with
an ephemeral CSPRNG nonce via HKDF-SHA256:

```
For each message:
  nonce = CSPRNG.random(32 bytes)
  For each byte i:
    sub_key[i] = HKDF(session_key || LLM_weight[i] || nonce || i)
```

This prevents many-times pad key reuse attacks.

---

## Layer 2: etherhive-mesh (Tailscale/Headscale)

Standard Tailscale mesh. All traffic already encrypted by etherhive-crypt.

---

## Layer 3: etherhive-ircd (IRC Daemon)

The chat protocol operates over the encrypted channels. Messages are
encrypted per-byte, stored in sealed memory.

---

## Trust Model

### Honesty-Auth: Identity Through Personality

No passwords. No OAuth. No email. Identity is a vector of deeply personal
answers. The trust model relies on the fact that an impostor cannot
consistently fake someone's life story over time.

- Stable fields (birth, names, constellation): must match exactly
- Volatile fields (song, mood, belief): can vary
- Overall match threshold: 80%
- Re-verification: every 30 days

This belongs in the Trust Model, not the Threat Model, because it is not
a cryptographic defense — it is a social/behavioral trust mechanism.

---

## Threat Model

This table describes the design's intended defenses. Per the status table
above, most rows below assume layers (VPN, mesh, per-byte LLM crypto,
sealed memory, SSH multihop) that are not currently wired into the running
daemon -- treat this as the target threat model, not the current one.

| Attack | Defense |
|--------|---------|
| Disk forensics | memfd — nothing on disk, ever |
| SSD wear-leveling recovery | SSH keys via /dev/fd pipes, tmpfs only |
| RAM cold boot | mlock'd regions, encrypted at rest in memory |
| /proc/PID/mem inspection | prctl(PR_SET_DUMPABLE, 0), MADV_DONTDUMP |
| Core dump analysis | RLIMIT_CORE = 0 |
| ptrace debugger attach | PR_SET_DUMPABLE = 0 |
| Quantum computer breaks Kyber | X25519 hybrid — classical ECDH still holds |
| Quantum computer breaks ECDH | Kyber-1024 — PQC KEM still holds |
| Session key leaked | Forward secrecy via rotation every N messages |
| LLM weights stolen | Pre-shared, never transmitted, unique per peer-pair |
| LLM weight timing side-channel | Load all 3 sub-keys, constant-time select (CMOV) |
| LLM weights as raw keystream | Combined with CSPRNG nonce via HKDF |
| Mullvad compromised | Tailscale WireGuard is second encryption layer |
| Tailscale compromised | Kyber+X25519 encryption already applied |
| Both compromised | Per-byte LLM sub-keys still protect each byte |
| Impersonation | Honesty-auth — see Trust Model |
| Replay attack | Per-message nonce + per-byte sub-key prevents reuse |
| Metadata analysis | Double-hop VPN hides source, Tailnet hides peer topology |
| mlock limit exceeded | CAP_IPC_LOCK via setcap, documented in setup |
| memfd seal prevents key rotation | crypto.mem keeps write access for rotation |

## Invariant: Zero External Integration

etherhive is a fully air-gapped messaging system. The following are PROHIBITED:

- URL/link sharing of any kind — all URLs are stripped from messages
- Egress connections — etherhive-ircd never connects outward except to peers
- External API calls — music.vaked.dev data is local choreography only, never fetched
- Image/media embedding — text-only protocol
- All integrations are LOCAL: choreographies live in sealed memory, never fetched
- Protocol commands are ASCII-only. Message bodies are UTF-8 for display.
- No Unicode in wire protocol — all commands use 7-bit ASCII for maximum compatibility.
  Display names may contain Unicode, but are transmitted as UTF-8 payloads.

