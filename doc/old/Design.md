# BIP-32 Extended Key Architecture for Multi-Protocol HSM Systems

## Overview

This document summarizes a structured approach to using BIP-32 as a **universal key hierarchy** across multiple protocols (Bitcoin, Lightning, SSH, X.509, etc.), combined with a **capability-based execution model** for secure vaults / HSMs.

---

# 1. Core Principle

Separate:

* **Key identity (derivation path)**
* **Key usage (function)**
* **Execution context (parameters)**

---

# 2. Key Derivation Structure (BIP-32)

## Recommended Path Schema

```
m / bip123' / id' / prot' / alg' / param' / variant' / config' / role / index
```

### Field Definitions

| Field      | Description                                      |
| ---------- | ------------------------------------------------ |
| `bip123'`  | Namespace / versioning                           |
| `id'`      | Tenant / entity / cluster                        |
| `prot'`    | Protocol (Bitcoin, Lightning, SSH, X.509, etc.)  |
| `alg'`     | Algorithm (ECDSA, Schnorr, RSA, Ed25519)         |
| `param'`   | Curve / key size / parameter set                 |
| `variant'` | Usage mode (MuSig2, PSS, adaptor, etc.)          |
| `config'`  | Environment / policy (mainnet, testnet, staging) |
| `role`     | Key purpose (address, channel, cert, auth, etc.) |
| `index`    | Leaf index                                       |

---

## Hardened vs Non-Hardened

```
m / bip123' / id' / prot' / alg' / param' / variant' / config' / role / index
      ↑ hardened ↑                                      ↑ non-hardened ↓
```

### Hardened Levels

* `bip123'`
* `id'`
* `prot'`
* `alg'`
* `param'`
* `variant'`
* `config'`

👉 Define **security boundaries**

### Non-Hardened Levels

* `role`
* `index`

👉 Enable safe derivation via xpub

---

# 3. Algorithm Model

## Structure

```
alg + param + variant
```

### Meaning

| Field     | Purpose                      |
| --------- | ---------------------------- |
| `alg`     | Cryptographic primitive      |
| `param`   | Curve / key size / parameter |
| `variant` | How the algorithm is used    |

---

## Examples

### Bitcoin (secp256k1)

```
alg'     = Schnorr
param'   = secp256k1
variant'
  0' = BIP340
  1' = MuSig2
  2' = adaptor signatures
```

---

### X.509

```
alg'     = RSA
param'   = 2048
variant'
  0' = PKCS#1 v1.5
  1' = PSS
```

---

### SSH

```
alg'     = Ed25519
param'   = fixed
variant'
  0' = standard
  1' = hardware-backed (FIDO)
```

---

# 4. Operation Model (Vault / HSM)

## Core Execution Model

```
result = F(keypath, function, params, payload)
```

---

## Request Structure

```
Request = {
  keypath,
  function,
  params,
  payload
}
```

### Components

| Field      | Description                             |
| ---------- | --------------------------------------- |
| `keypath`  | Selects key (BIP-32 path)               |
| `function` | Operation (sign, derive, decrypt, etc.) |
| `params`   | Operation-specific parameters           |
| `payload`  | Data to operate on                      |

---

# 5. Function Code Architecture

## Function Code Ranges

| Range | Category | Description |
|-------|----------|-------------|
| 0–15  | Generic  | Work the same regardless of protocol |
| 16+   | Protocol-specific | Specializations requiring protocol-aware behavior |

## Generic Functions (0–15)

| Code | Name | Description |
|------|------|-------------|
| 0 | `EXPORT_SEED` | Export raw 32-byte BIP-32 leaf key material |
| 1 | `GET_PUBLIC_KEY` | Derive and export the public key (algorithm-aware) |
| 2 | `SIGN` | Sign payload — standard signature, no protocol framing |

Generic functions are protocol-agnostic. `EXPORT_SEED` may be disabled in
production vaults to prevent key material exfiltration. `GET_PUBLIC_KEY`
must remain available since it is the only way to obtain the public key
when the seed cannot leave the vault. `SIGN` produces a raw cryptographic
signature without protocol-specific framing.

## Protocol-Specific Functions (16+)

These extend generic functions when a protocol needs behavior beyond a
plain signature (additional framing, multi-step operations, encryption).

### Bitcoin / Lightning

* `schnorr_sign`
* `musig2_partial_sign`
* `sign_commitment`
* `sign_htlc`

---

### SSH

* `ssh_sign` — sign with SSH wire-format framing (algorithm name prefix, agent flags)

---

### X.509

* `sign_certificate`
* `sign_crl`

---

### Nostr

* `sign_event`
* `nip44_encrypt`
* `nip44_decrypt`

---

# 6. Parameter Examples

## Transaction Signing

```
params = {
  sighash_type,
  input_index,
  tapleaf_hash,
  annex_present
}
```

---

## MuSig2

```
params = {
  session_id,
  nonce_commitment,
  participant_index
}
```

---

## X.509

```
params = {
  digest_algorithm,
  validity_profile,
  key_usage
}
```

---

# 7. Design Decisions

## Fixed Path Structure (Recommended)

✔ Stable
✔ Easy to parse
✔ Easy to audit
✔ HSM-friendly

---

## Avoid Dynamic Path Depth

❌ Different structures per algorithm
❌ Complex parsing
❌ Hard to secure

---

## Use Default Values

Unused fields:

```
param'   = 0'
variant' = 0'
```

---

# 8. Security Model

## Each Hardened Level = Security Boundary

* Tenant isolation → `id'`
* Protocol isolation → `prot'`
* Cryptographic isolation → `alg'`
* Domain separation → `variant'`
* Environment isolation → `config'`

---

## Policy Enforcement

Example rules:

* Lightning keys → only `musig2_partial_sign`
* X.509 keys → only `sign_certificate`
* RSA keys → forbid decrypt (optional policy)

---

## Domain Separation

Ensure signatures are bound to context:

```
H = hash(keypath, function, params, payload)
```

---

# 9. Performance Considerations

* Each path level = 1 HMAC-SHA512
* Cost = O(depth)
* Memory usage ≈ constant
* Smartcards handle ~10–20 levels easily

---

# 10. Key Insight

> The path defines **where the key lives**
> The function defines **what the key does**
> The params define **how it is used**

---

# Final Architecture Summary

## Key Identity

```
m / bip123' / id' / prot' / alg' / param' / variant' / config' / role / index
```

## Execution

```
result = vault.execute({
  keypath,
  function,
  params,
  payload
})
```

---

This model provides:

✔ deterministic key hierarchy
✔ multi-protocol support
✔ strong domain separation
✔ HSM-compatible policy enforcement
✔ future-proof extensibility

---
