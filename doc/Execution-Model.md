# Vault Execution Model

This document describes the execution model for vault/HSM operations. For key
derivation and path structure, see
[BIP-44-Multi-Protocol-Key-Derivation.md](BIP-44-Multi-Protocol-Key-Derivation.md).

---

## Core Principle

The derivation path selects **which key**. Operations are specified separately.
Runtime parameters like hash algorithm, padding scheme, and sighash types do
not affect key derivation — they are passed at execution time.

---

## Request Structure

```
result = vault.execute({
    keypath,
    function,
    params,
    payload
})
```

| Field | Description |
|-------|-------------|
| `keypath` | Selects the key (BIP-32 derivation path) |
| `function` | Operation to perform |
| `params` | Operation-specific parameters (hash algorithm, padding, etc.) |
| `payload` | Data to operate on |

---

## Function Code Ranges

Function codes are divided into two ranges:

| Range | Category | Description |
|-------|----------|-------------|
| 0–15  | Generic  | Work the same regardless of protocol. Every vault implementation supports these. |
| 16+   | Protocol-specific | Specializations for SSH, Bitcoin, Nostr, etc. that need protocol-aware behavior. |

### Generic Functions (0–15)

| Code | Name | Description |
|------|------|-------------|
| 0 | `EXPORT_SEED` | Export raw 32-byte BIP-32 leaf key material. May be disabled in production vaults. |
| 1 | `GET_PUBLIC_KEY` | Derive and export the public key (algorithm-aware). |
| 2 | `SIGN` | Sign payload with the key at the given path. Standard signature, no protocol framing. |

### Protocol-Specific Functions (16+)

These extend or specialize the generic functions when a protocol requires
behavior beyond a plain signature (e.g. additional framing, parameters, or
multi-step operations).

#### Bitcoin / Lightning

- `schnorr_sign`
- `musig2_partial_sign`
- `sign_commitment`
- `sign_htlc`

#### SSH

- `ssh_sign` — sign with SSH wire-format framing (algorithm name prefix, agent flags)

#### X.509

- `sign_certificate`
- `sign_crl`

#### Nostr

- `sign_event`
- `nip44_encrypt`
- `nip44_decrypt`

---

## Parameter Examples

### Transaction Signing (Bitcoin)

```
params = {
    sighash_type,
    input_index,
    tapleaf_hash,
    annex_present
}
```

### MuSig2 (Bitcoin / Lightning)

```
params = {
    session_id,
    nonce_commitment,
    participant_index
}
```

### RSA Signing (SSH / X.509)

```
params = {
    hash_algo,       // SHA-256, SHA-512
    padding          // PKCS1v15, PSS
}
```

### X.509 Certificate Signing

```
params = {
    digest_algorithm,
    validity_profile,
    key_usage
}
```

---

## Design Principle

> The path defines **where the key lives**.
> The function defines **what the key does**.
> The params define **how it is used**.
