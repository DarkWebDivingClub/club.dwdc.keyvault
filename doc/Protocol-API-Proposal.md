# Protocol API Proposal

## Overview

Each protocol (SSH, GPG, S/MIME, TLS, Nostr) exposes a subset of five core
wire operations. These are KM-level operations — KM implements them by
composing KV primitives and adding protocol-specific logic.

The protocol context is established by the service channel. The operation
and its parameters travel on the wire. KM resolves the keypath from the
identity and protocol, then composes the appropriate KV calls.

## Layered Responsibilities

```
protocol_avatar:    local protocol translation → wire operations
protocol_service:   protocol-aware — composes KV primitives into protocol operations
KV:                 minimal — private key primitives only
```

### keymaster_avatar

The local process representing KeyMaster. Contains `protocol_avatars`
that each handle a specific protocol's local interface.

| protocol_avatar  | Local Interface              | Wire Channel    |
|------------------|------------------------------|-----------------|
| `ssh_avatar`     | SSH agent protocol           | SSH channel     |
| `gpg_avatar`     | PKCS#11 socket (via scdaemon)| GPG channel     |
| `nostr_avatar`   | Nostr client interface       | Nostr channel   |
| `smime_avatar`   | PKCS#11 socket               | S/MIME channel  |
| `tls_avatar`     | PKCS#11 socket               | TLS channel     |

Each `protocol_avatar` is responsible for speaking whatever the local
version of the protocol is and forwarding wire operations on its Nostr
service channel.

### KeyMaster (protocol_services)

Inside KeyMaster, each protocol has a corresponding `protocol_service`
that handles the KM side of the service channel:

| protocol_service | Wire Channel    | KV Calls                          |
|------------------|-----------------|-----------------------------------|
| SSH service      | SSH channel     | `GET_PUBLIC_KEY`, `SIGN`          |
| GPG service      | GPG channel     | `GET_PUBLIC_KEY`, `SIGN`, `RAW_DECRYPT` |
| Nostr service    | Nostr channel   | `GET_PUBLIC_KEY`, `SIGN`, `RAW_DERIVE`  |
| S/MIME service   | S/MIME channel  | `GET_PUBLIC_KEY`, `SIGN`, `RAW_DECRYPT`, `RAW_DERIVE` |
| TLS service      | TLS channel     | `GET_PUBLIC_KEY`, `SIGN`, `RAW_DERIVE`  |

The `protocol_service` resolves the keypath from identity and protocol,
composes KV primitives, and handles protocol-specific logic (framing,
padding, symmetric crypto for compound operations).

### Full Architecture

```
Local machine (keymaster_avatar)             KeyMaster
┌──────────────────────────────┐            ┌──────────────────────┐
│  ssh_avatar   ─── SSH channel ──────────── SSH service          │
│  gpg_avatar   ─── GPG channel ──────────── GPG service          │
│  nostr_avatar ─── Nostr channel ────────── Nostr service        │
│  smime_avatar ─── S/MIME channel ────────── S/MIME service       │
│  tls_avatar   ─── TLS channel ──────────── TLS service          │
└──────────────────────────────┘            └──────────┬───────────┘
                                                       │
                                                       KV
```

## KV Primitives

KV executes: `result = vault.execute(keypath, function, params, payload)`

KV provides four primitives. It has no protocol knowledge.

| Primitive          | KV Code | Description                                   |
|--------------------|---------|-----------------------------------------------|
| `GET_PUBLIC_KEY`   | 1       | Derive and return the public key              |
| `SIGN`             | 2       | Sign payload with private key                 |
| `RAW_DECRYPT`      | —       | Asymmetric decrypt (RSA private key operation)|
| `RAW_DERIVE`       | —       | ECDH: private key + peer public key → shared secret |

## Wire Operations

Five operations cover all protocols. These travel on the Nostr service
channels between Avatar and KM.

| Operation      | Description                                         |
|----------------|-----------------------------------------------------|
| `list_keys`    | Enumerate available public keys                     |
| `sign`         | Sign data or hash                                   |
| `decrypt`      | Decrypt ciphertext (protocol-specific scheme)       |
| `encrypt`      | Encrypt plaintext (protocol-specific scheme)        |
| `derive`       | Key agreement (ECDH shared secret)                  |

## Protocol APIs

### SSH

| Operation    | Key Type | Notes                     |
|-------------|----------|---------------------------|
| `list_keys` | Ed25519  |                           |
| `sign`      | Ed25519  | Raw data, agent flags     |

### GPG (OpenPGP)

| Operation    | Key Type | Notes                              |
|-------------|----------|------------------------------------|
| `list_keys` | RSA      | Returns modulus, exponent, keygrip |
| `sign`      | RSA      | Hash + algorithm ID                |
| `decrypt`   | RSA      | PKCS#1 v1.5 or OAEP               |

### S/MIME

| Operation    | Key Type   | Notes                        |
|-------------|------------|------------------------------|
| `list_keys` | RSA or EC  |                              |
| `sign`      | RSA or EC  | Hash + algorithm ID          |
| `decrypt`   | RSA        | Envelope decryption          |
| `derive`    | EC (ECDH)  | Key agreement for encryption |

### TLS (Client Certificate)

| Operation    | Key Type  | Notes                     |
|-------------|-----------|---------------------------|
| `list_keys` | EC        |                           |
| `sign`      | EC        | TLS CertificateVerify     |
| `derive`    | EC (ECDH) | Key exchange              |

### Nostr

| Operation    | Key Type          | Notes                    |
|-------------|-------------------|--------------------------|
| `list_keys` | secp256k1 Schnorr |                          |
| `sign`      | secp256k1 Schnorr | NIP-01 event signing     |
| `encrypt`   | secp256k1         | NIP-44 encrypt           |
| `decrypt`   | secp256k1         | NIP-44 decrypt           |

## Summary Matrix

```
             list_keys  sign  decrypt  encrypt  derive
  SSH            x        x
  GPG            x        x      x
  S/MIME         x        x      x                 x
  TLS            x        x                        x
  Nostr          x        x      x        x
```

## How KM Composes Wire Operations from KV Primitives

KM is protocol-aware. It translates wire operations into KV primitive calls,
handling protocol-specific framing, padding, and compound operations.

### list_keys

KM resolves identity + protocol to keypath, calls KV `GET_PUBLIC_KEY`,
formats the result for the protocol (SSH key blob, RSA modulus+exponent, etc).

| Wire operation | KM does                                        |
|----------------|------------------------------------------------|
| `list_keys`    | KV `GET_PUBLIC_KEY` → format for protocol      |

### sign

The raw signing is always KV `SIGN`. KM handles protocol framing.

| Protocol | KM does                                                     |
|----------|-------------------------------------------------------------|
| SSH      | KV `SIGN(data)` → wrap in SSH signature format              |
| GPG      | KV `SIGN(hash)` → raw RSA signature                        |
| S/MIME   | KV `SIGN(hash)` → raw signature                            |
| TLS      | KV `SIGN(hash)` → raw signature                            |
| Nostr    | KV `SIGN(event_hash)` → Schnorr signature                  |

### decrypt

Two cases depending on key type:

| Protocol | Key Type | KM does                                          |
|----------|----------|--------------------------------------------------|
| GPG      | RSA      | KV `RAW_DECRYPT(ciphertext)` → handle PKCS#1 padding |
| S/MIME   | RSA      | KV `RAW_DECRYPT(ciphertext)` → unwrap envelope   |
| Nostr    | EC       | KV `RAW_DERIVE(sender_pubkey)` → shared secret → HKDF → ChaCha20-Poly1305 decrypt |

For EC-based decryption, there is no asymmetric "decrypt". KM calls KV
`RAW_DERIVE` to get the shared secret, then performs the symmetric
decryption (HKDF + ChaCha20-Poly1305 for NIP-44, AES for S/MIME) itself.

### encrypt

Same pattern — KM does key agreement via KV, then symmetric crypto.

| Protocol | KM does                                                      |
|----------|--------------------------------------------------------------|
| Nostr    | KV `RAW_DERIVE(recipient_pubkey)` → shared secret → HKDF → ChaCha20-Poly1305 encrypt |

### derive

Thin wrapper — KM calls KV directly.

| Protocol | KM does                                                 |
|----------|---------------------------------------------------------|
| S/MIME   | KV `RAW_DERIVE(peer_pubkey)` → shared secret            |
| TLS      | KV `RAW_DERIVE(peer_pubkey)` → shared secret            |

## KeyPath Resolution

KM resolves the keypath from identity and protocol before any KV call:

```
Master Seed
  → Sub Seed (count)
    → Identity Seed (e.g. "alice@atlanta.com")
      → Protocol Seed (e.g. "ssh", "openpgp", "nostr")
        → Key Pair (via ChaCha20 CSPRNG)
```

The wire operations carry identity and protocol context implicitly via the
service channel. KM knows which protocol a channel serves.

## Implications

1. **KV stays minimal**: four primitives, no protocol knowledge
2. **protocol_services are protocol-aware**: compose KV primitives, handle
   framing, padding, symmetric crypto for compound operations
   (NIP-44, S/MIME EC)
3. **Each protocol_avatar handles local protocol conversion**: `ssh_avatar`
   speaks SSH agent protocol, `gpg_avatar` speaks PKCS#11 (via scdaemon),
   etc. Each forwards wire operations on its own Nostr service channel.
4. **PKCS#11 libraries**: where applicable, a PKCS#11 shared library
   translates C API calls (`C_FindObjects`, `C_Sign`, `C_Decrypt`,
   `C_DeriveKey`) to the `protocol_avatar` socket, one library per
   protocol pointing at the corresponding avatar socket
5. **Channel separation**: each protocol has its own Nostr service channel
   with its own keypair, carrying only the operations relevant to that
   protocol
