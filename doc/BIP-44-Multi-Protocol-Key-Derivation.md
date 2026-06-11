# BIP-44 Multi-Protocol Key Derivation

## Overview

This document describes a key derivation scheme for multi-protocol HSM/vault systems
built on BIP-32 hierarchical deterministic key derivation, using the existing BIP-44
path structure and SLIP-44 protocol registry.

The scheme supports multiple cryptographic protocols (Bitcoin, Nostr, SSH, X.509,
OpenPGP, etc.) from a single master seed, with algorithm isolation, key rotation,
and HSM/smart card compatibility.

---

## Path Structure

```
m / 44' / prot' / id' / alg' / config'
```

Five levels. Conforms to BIP-44 depth convention. Each level can be hardened or
non-hardened depending on the protocol's requirements.

| Level | Field | Description |
|-------|-------|-------------|
| 1 | `44'` | BIP-44 purpose (standard, already exists) |
| 2 | `prot'` | Protocol identifier from SLIP-44 registry |
| 3 | `id'` | Identity / account |
| 4 | `alg'` | Algorithm, variant, and role (packed) |
| 5 | `config'` | CSPRNG and key index/rotation (packed) |

---

## Level 2: Protocol (`prot'`)

Registered in the existing SLIP-44 coin type registry. Non-coin protocols follow
the precedent set by Nostr (1237).

| Value | Protocol |
|-------|----------|
| `0` | Bitcoin |
| `1237` | Nostr |
| TBD | SSH |
| TBD | X.509 |
| TBD | OpenPGP |

New protocols are added via SLIP-44 pull request.

---

## Level 3: Identity (`id'`)

| Value | Meaning |
|-------|---------|
| `0` | Default identity (recommended for most users) |
| `hash(name)` | Named identity, hashed to 31 bits |

### Identity Hashing

For named identities, the identity string (e.g. `"alice@home.com"`) is hashed
using SHA-256, truncated to the lower 31 bits:

```
id = SHA-256("alice@home.com")[0..31] & 0x7FFFFFFF
```

This makes named identities optional. Most users use `id = 0`. Named identities
are available when multiple identities are needed under the same protocol.

---

## Level 4: Algorithm (`alg'`)

### Bit Layout (32 bits)

```
Bit 31                                                          Bit 0
+------+--------------------------+----------------+------------------+
|  H   |       alg (15 bits)     | variant (8 bits)|   role (8 bits)  |
|      |       bits 30-16        | bits 15-8       |  bits 7-0        |
+------+--------------------------+----------------+------------------+
```

| Field | Bits | Range | Description |
|-------|------|-------|-------------|
| H | 31 | 0-1 | BIP-32 hardened flag |
| alg | 30-16 | 0-32767 | Algorithm identifier from published table |
| variant | 15-8 | 0-255 | Algorithm parameters (key size, curve) |
| role | 7-0 | 0-255 | Key purpose/role from per-protocol table |

### Algorithm Table

Published global table. Schnorr is assigned `0` so that Bitcoin and Nostr
(the most common use cases) produce all-zero `alg` fields in the default
configuration.

| Value | Algorithm |
|-------|-----------|
| 0 | Schnorr |
| 1 | Ed25519 |
| 2 | RSA |
| 3 | ECDSA |
| 4 | Ed448 |
| 5 | ML-DSA (Dilithium) |
| 6 | SLH-DSA (SPHINCS+) |
| 7 | ML-KEM (Kyber) |
| 8 | Falcon |
| ... | ... |

Each protocol specification defines which algorithms from this table are
supported. Not all algorithms are valid for all protocols.

### Variant Table

Per-algorithm table. Interpretation depends on the algorithm.

#### Schnorr

| Value | Curve |
|-------|-------|
| 0 | secp256k1 |

#### Ed25519

| Value | Meaning |
|-------|---------|
| 0 | Default (only option) |

#### RSA

The variant value encodes the key size divided by 256:

```
variant = key_size / 256
```

| Value | Key Size |
|-------|----------|
| 2 | 512 |
| 3 | 768 |
| 4 | 1024 |
| 8 | 2048 |
| 12 | 3072 |
| 16 | 4096 |
| 32 | 8192 |
| 64 | 16384 |

No lookup table needed. The key size is derived directly: `key_size = variant * 256`.

#### ECDSA

| Value | Curve |
|-------|-------|
| 0 | secp256k1 |
| 1 | P-256 (secp256r1) |
| 2 | P-384 (secp384r1) |
| 3 | P-521 (secp521r1) |
| 4 | Brainpool P256r1 |
| 5 | Brainpool P384r1 |
| 6 | Brainpool P512r1 |

#### Ed448

| Value | Meaning |
|-------|---------|
| 0 | Default (only option) |

#### ML-DSA (Dilithium)

| Value | Variant |
|-------|---------|
| 0 | ML-DSA-44 |
| 1 | ML-DSA-65 |
| 2 | ML-DSA-87 |

#### SLH-DSA (SPHINCS+)

| Value | Variant |
|-------|---------|
| 0 | SLH-DSA-128s (SHA2) |
| 1 | SLH-DSA-128f (SHA2) |
| 2 | SLH-DSA-192s (SHA2) |
| 3 | SLH-DSA-192f (SHA2) |
| 4 | SLH-DSA-256s (SHA2) |
| 5 | SLH-DSA-256f (SHA2) |
| 6 | SLH-DSA-128s (SHAKE) |
| 7 | SLH-DSA-128f (SHAKE) |
| 8 | SLH-DSA-192s (SHAKE) |
| 9 | SLH-DSA-192f (SHAKE) |
| 10 | SLH-DSA-256s (SHAKE) |
| 11 | SLH-DSA-256f (SHAKE) |

### Role Tables (per protocol)

The role field (8 bits, range 0-255) is defined per protocol.

#### SSH

| Value | Role |
|-------|------|
| 0 | User authentication |
| 1 | Host key |

#### X.509

| Value | Role |
|-------|------|
| 0 | CA signing |
| 1 | TLS server |
| 2 | TLS client |
| 3 | Code signing |
| 4 | S/MIME (email) |

#### Bitcoin

| Value | Role |
|-------|------|
| 0 | Receive |
| 1 | Change |

#### Nostr

| Value | Role |
|-------|------|
| 0 | Identity |
| 1 | Delegation |

---

## Level 5: Configuration (`config'`)

### Bit Layout (32 bits)

```
Bit 31                                                Bit 0
+------+-----------------+--------------------------------+
|  H   | csprng (7 bits) |  index/rotation (24 bits)      |
|      | bits 30-24      |  bits 23-0                     |
+------+-----------------+--------------------------------+
```

| Field | Bits | Range | Description |
|-------|------|-------|-------------|
| H | 31 | 0-1 | BIP-32 hardened flag |
| csprng | 30-24 | 0-127 | CSPRNG type; `0` = none (use raw 32 bytes) |
| index | 23-0 | 0-16777215 | Key index / rotation counter |

The index occupies the lower 24 bits (3 bytes), giving a clean byte-aligned
split. This level places the key index at the end of the path, matching the
position of `address_index` in BIP-44's Bitcoin convention. The field that
changes most frequently (the counter) is at the deepest level.

### CSPRNG Table

Published global table. Used when the algorithm requires more than 32 bytes of
entropy for key generation (e.g. RSA prime generation).

| Value | CSPRNG | Specification |
|-------|--------|---------------|
| 0 | None — use the 32 bytes from BIP-32 derivation as the key directly | — |
| 1 | HMAC-DRBG (SHA-256) | NIST SP 800-90A Rev.1 |
| 2 | CTR-DRBG (AES-256) | NIST SP 800-90A Rev.1 |
| 3 | ChaCha20 | RFC 7539 (seeding convention defined below) |
| ... | ... | ... |

**HMAC-DRBG (`csprng = 1`) is the recommended default** for algorithms that
require a CSPRNG. It is NIST standardized (SP 800-90A), FIPS 140-2/3 approved,
and requires only SHA-256 — which is universally available across all target
platforms including Java Card (NXP JCOP), RISC-V secure elements (TROPIC01),
and general-purpose CPUs.

Production-quality implementations exist for all major platforms:

- **Java**: BouncyCastle `HMacSP800DRBG` / `SP800SecureRandomBuilder`
- **Rust**: `hmac-drbg` crate (`no_std` compatible for bare-metal targets)
- **C**: OpenSSL, mbedTLS, wolfSSL

Algorithms where the 32-byte BIP-32 output is the private key (Ed25519, ECDSA,
Schnorr) use `csprng = 0`. Algorithms that need a CSPRNG for key generation (RSA)
should use `csprng = 1` (HMAC-DRBG) unless platform-specific constraints require
an alternative.

### CSPRNG Seeding

For all CSPRNGs, the 32 bytes from the BIP-32 leaf derivation are used as the
seed. The CSPRNG must be initialized deterministically — the same seed must
always produce the same byte stream.

#### HMAC-DRBG (csprng = 1)

Initialized per NIST SP 800-90A Section 10.1.2 with:

- `entropy_input`: the 32-byte BIP-32 leaf key
- `nonce`: empty
- `personalization_string`: empty
- `security_strength`: 256 bits

No reseeding is performed. The DRBG runs in a purely deterministic mode.

#### CTR-DRBG (csprng = 2)

Initialized per NIST SP 800-90A Section 10.2 with AES-256 and:

- `entropy_input`: the 32-byte BIP-32 leaf key
- `nonce`: empty
- `personalization_string`: empty

#### ChaCha20 (csprng = 3)

Initialized per RFC 7539 with:

- `key`: SHA-256 of the 32-byte BIP-32 leaf key (32 bytes)
- `nonce`: first 12 bytes of the BIP-32 leaf key
- Output is the ChaCha20 keystream starting from block counter 0

### Index / Rotation

The index field provides key rotation within the same role. Most users will
always use `index = 0`. If a key is compromised or needs to be replaced,
increment the index to derive a new key without changing any other part of
the path.

---

## Leaf Output

The BIP-32 derivation at the final level produces 32 bytes. How these bytes
become a key depends on the `csprng` field:

| CSPRNG value | Behavior |
|-------------|----------|
| `0` (none) | The 32 bytes **are** the private key |
| `1+` (HMAC-DRBG, etc.) | The 32 bytes **seed** the specified CSPRNG, which feeds a `KeyPairGenerator` |

### Direct key (csprng = 0)

Used by Ed25519, ECDSA, Schnorr, Ed448, and post-quantum algorithms. The 32
bytes from BIP-32 derivation are used as the private key directly (or as the
seed for algorithms with specific seed formats).

### CSPRNG-derived key (csprng >= 1)

Used by RSA and other algorithms that require more than 32 bytes of entropy.
The 32 bytes initialize the specified CSPRNG, producing a deterministic byte
stream that feeds the key pair generator.

```
BIP-32 leaf (32 bytes) --> CSPRNG --> KeyPairGenerator --> Key Pair
```

The same seed + same CSPRNG always produces the same key pair.

---

## Example Paths

### Nostr (default)

```
m / 44' / 1237' / 0' / 0' / 0'
                   |    |    |
                   |    |    +-- csprng=0 (raw), index=0
                   |    +------- alg=0 (Schnorr), variant=0 (secp256k1), role=0 (identity)
                   +------------ default identity
```

All zeros after the protocol. The simplest possible path.

### Bitcoin (default)

```
m / 44' / 0' / 0' / 0' / 0'
               |    |    |
               |    |    +-- csprng=0 (raw), index=0
               |    +------- alg=0 (Schnorr), variant=0 (secp256k1), role=0 (receive)
               +------------ default identity
```

Same as Nostr — only the protocol number differs.

### Bitcoin (change address)

```
m / 44' / 0' / 0' / 0x00000001' / 0'
               |    |              |
               |    |              +-- csprng=0 (raw), index=0
               |    +----------------- alg=0 (Schnorr), variant=0 (secp256k1), role=1 (change)
               +---------------------- default identity
```

Role=1 (change) is packed into the lowest 8 bits of Level 4.

### SSH Ed25519

```
m / 44' / XXXX' / 0' / 0x00010000' / 0'
                   |    |              |
                   |    |              +-- csprng=0 (raw), index=0
                   |    +----------------- alg=1 (Ed25519), variant=0, role=0 (user auth)
                   +---------------------- default identity
```

### SSH RSA-4096

```
m / 44' / XXXX' / 0' / 0x00021000' / 0x01000000'
                   |    |              |
                   |    |              +-- csprng=1 (HMAC-DRBG), index=0
                   |    +----------------- alg=2 (RSA), variant=16 (4096/256), role=0 (user auth)
                   +---------------------- default identity
```

Level 5 value: `(1 << 24) | 0 = 0x01000000`.

### X.509 CA Signing RSA-2048, rotated once

```
m / 44' / YYYY' / hash("corp.com")' / 0x00020800' / 0x01000001'
                   |                    |              |
                   |                    |              +-- csprng=1 (HMAC-DRBG), index=1
                   |                    +----------------- alg=2 (RSA), variant=8 (2048/256), role=0 (CA signing)
                   +-------------------------------------- named identity
```

Level 5 value: `(1 << 24) | 1 = 0x01000001`.

---

## Comparison with Existing Standards

### NIP-06 (Nostr)

| | NIP-06 | This scheme |
|---|---|---|
| Path | `m/44'/1237'/0'/0/0` | `m/44'/1237'/0'/0'/0'` |
| Depth | 5 | 5 |
| SLIP-44 | 1237 (same) | 1237 (same) |
| Algorithm | Implicit | Explicit (Schnorr = 0) |
| Rotation | Bump account | Index field in Level 5 |
| Compatible | - | Different keys (hardened vs non-hardened) |

### BIP-44 (Bitcoin)

| | BIP-44 | This scheme |
|---|---|---|
| Path | `m/44'/0'/0'/0/0` | `m/44'/0'/0'/0'/0'` |
| Depth | 5 | 5 |
| SLIP-44 | 0 (same) | 0 (same) |
| Level 4 | change (0/1) | alg + variant + role |
| Level 5 | address_index | csprng + index |
| Algorithm | Implicit | Explicit (Schnorr = 0) |
| Compatible | - | Different keys (hardened vs non-hardened) |

The index/rotation counter at Level 5 aligns with BIP-44's `address_index`
position — the counter that changes most frequently is at the deepest level.

---

## Hardened vs Non-Hardened

Each protocol specification defines which levels use hardened derivation.
The hardened flag (bit 31) is independent of the packed data fields.

**Recommended defaults:**

| Protocol | prot | id | alg | config |
|----------|------|----|-----|--------|
| Bitcoin | H | H | H | non-H (xpub derivation) |
| Nostr | H | H | H | H |
| SSH | H | H | H | H |
| X.509 | H | H | H | H |

Non-hardened levels enable xpub-based public key derivation without exposing
the private key. This is primarily useful for Bitcoin (watching wallets).
Most other protocols use all-hardened paths.

---

## Published Tables Summary

| Table | Scope | Maintained by | Size |
|-------|-------|---------------|------|
| Protocol | SLIP-44 registry | SatoshiLabs | Existing + new entries |
| Algorithm | Global | This specification | ~10 entries |
| Variant | Per algorithm | This specification | ~5-12 entries each |
| Role | Per protocol | Per-protocol specification | ~2-5 entries each |
| CSPRNG | Global | This specification | ~5 entries |
| Identity hash | Global | This specification | One algorithm (SHA-256) |

---

## Security Properties

1. **Deterministic** - same seed + same path = same key, every time
2. **Algorithm isolation** - different `alg` values derive from different branches
3. **Variant isolation** - different key sizes or curves derive different keys
4. **Role isolation** - different roles derive different keys
5. **Rotation isolation** - rotated keys are cryptographically independent
6. **No private key storage** - only path metadata is persisted; keys are regenerated on demand
7. **Single seed backup** - the master mnemonic recovers all keys for all protocols
8. **Forward derivation only** - child keys cannot reveal parent or sibling keys (hardened levels)
9. **HSM/smart card compatible** - fixed depth, numeric indices, small published tables

---

## Design Decisions

### Why BIP-44 depth (5 levels)?

Matches the established convention. No new BIP purpose number needed.
Existing tooling recognizes the structure. Each level has a clear purpose.

### Why packed bit fields?

Keeps the path at 5 levels while encoding algorithm, variant, role, CSPRNG,
and index/rotation. Without packing, these would require 8+ levels.

### Why role in Level 4 and index in Level 5?

Level 4 defines **what** the key is: the algorithm, its parameters, and its
purpose. Level 5 defines **which instance**: the CSPRNG used for generation
and the rotation counter. This places the index at the deepest level,
matching BIP-44's convention where `address_index` is in the last position.
The field that changes most frequently is at the end.

### Why published tables instead of hashing?

Ensures deterministic interoperability across implementations. No ambiguity
about string canonicalization. Auditable on constrained devices.

### Why CSPRNG in the path?

Two implementations using different CSPRNGs from the same seed would produce
different RSA keys. Making the CSPRNG part of the key identity ensures
reproducibility.

### Why HMAC-DRBG as the default CSPRNG?

HMAC-DRBG (NIST SP 800-90A) is the recommended default because:

- Only requires SHA-256 — universally available on all target hardware
- NIST standardized and FIPS approved — no custom seeding conventions needed
- Works on Java Card (NXP JCOP), RISC-V secure elements (TROPIC01), and
  general-purpose CPUs
- Production-quality implementations in Java (BouncyCastle), Rust (`hmac-drbg`,
  `no_std`), and C (OpenSSL, mbedTLS)
- Formally analyzed with provable security reduction to the underlying hash

CTR-DRBG and ChaCha20 are provided as alternatives for platforms where AES
hardware acceleration or ARX-optimized software (respectively) offer better
performance. The CSPRNG speed is not the bottleneck for RSA key generation
(primality testing dominates), so the choice is primarily about hardware
availability and standards compliance.

### Why RSA variant = key_size / 256?

All standard RSA key sizes are multiples of 256. Dividing by 256 fits any
practical key size into 8 bits without a lookup table.

### Why identity hashing is optional?

Most users have one identity per protocol. Forcing a hash computation for
the common case (`id = 0`) adds complexity without benefit.
