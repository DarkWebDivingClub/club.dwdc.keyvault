# SSH Protocol: Cryptographic Operations Requiring Private Key Access

This document catalogs every SSH protocol operation that requires private key
material -- the operations a vault/HSM must implement to serve as an SSH
key custodian. Symmetric transport operations (AES, ChaCha20-Poly1305) are
excluded because they use ephemeral session keys, not identity keys.

---

## 1. SSH Key Types (Identity Keys)

These are the public key algorithm identifiers defined by RFCs and used for
host keys, user keys, and CA keys. Each one implies a specific signing
algorithm that the vault must support.

### 1.1 RSA Family

| Algorithm ID       | Signing Scheme         | Hash   | Key Format           | RFC       |
|--------------------|------------------------|--------|----------------------|-----------|
| `ssh-rsa`          | RSASSA-PKCS1-v1_5      | SHA-1  | `(e, n)` as mpints   | RFC 4253  |
| `rsa-sha2-256`     | RSASSA-PKCS1-v1_5      | SHA-256| Same `ssh-rsa` blob  | RFC 8332  |
| `rsa-sha2-512`     | RSASSA-PKCS1-v1_5      | SHA-512| Same `ssh-rsa` blob  | RFC 8332  |

**Critical detail:** `rsa-sha2-256` and `rsa-sha2-512` reuse the `ssh-rsa`
public key encoding (`string "ssh-rsa", mpint e, mpint n`). The key blob
on disk and in the agent is identical; only the signature algorithm differs.
A vault holding an RSA key must be able to produce signatures under any of the
three algorithms.

### 1.2 DSA

| Algorithm ID | Signing Scheme | Hash   | Key Format               | RFC      |
|-------------|----------------|--------|--------------------------|----------|
| `ssh-dss`   | DSA (FIPS 186) | SHA-1  | `(p, q, g, y)` as mpints| RFC 4253 |

DSA is deprecated (RFC 9142 recommends against it; OpenSSH disabled it by
default since 7.0). The vault may choose not to support it.

### 1.3 ECDSA Family (NIST Curves)

| Algorithm ID                | Curve      | Hash    | Key Format                     | RFC      |
|-----------------------------|------------|---------|--------------------------------|----------|
| `ecdsa-sha2-nistp256`       | P-256      | SHA-256 | `(curve_name, Q)` Q=uncompressed point | RFC 5656 |
| `ecdsa-sha2-nistp384`       | P-384      | SHA-384 | `(curve_name, Q)`              | RFC 5656 |
| `ecdsa-sha2-nistp521`       | P-521      | SHA-512 | `(curve_name, Q)`              | RFC 5656 |

Signature output: two mpints `(r, s)` encoded per SEC1/RFC 5656.

### 1.4 EdDSA Family (Edwards Curves)

| Algorithm ID    | Curve        | Hash (internal) | Key Format       | RFC      |
|-----------------|--------------|-----------------|------------------|----------|
| `ssh-ed25519`   | Ed25519      | SHA-512         | 32 bytes `ENC(A)`| RFC 8709 |
| `ssh-ed448`     | Ed448        | SHAKE256        | 57 bytes `ENC(A)`| RFC 8709 |

Signature output: 64 bytes (Ed25519) or 114 bytes (Ed448), produced per
RFC 8032 sections 5.1.6 and 5.2.6 respectively.

**Ed25519 note:** The signing algorithm per RFC 8032 is deterministic -- the
nonce is derived from the private key and the message via SHA-512. This means
the vault must hold the full 32-byte Ed25519 seed (or expanded 64-byte
private key) and perform the complete signing internally. There is no
"pre-hash then sign" split possible with pure Ed25519.

### 1.5 FIDO/U2F Security Key Types (OpenSSH Extensions)

| Algorithm ID                            | Base Algorithm      | Defined In          |
|-----------------------------------------|---------------------|---------------------|
| `sk-ecdsa-sha2-nistp256@openssh.com`    | ECDSA P-256         | OpenSSH PROTOCOL.u2f|
| `sk-ssh-ed25519@openssh.com`            | Ed25519             | OpenSSH PROTOCOL.u2f|

These are hardware-bound keys where the signing operation occurs inside a
FIDO2/U2F authenticator. The signature includes additional fields (flags byte,
counter) that are not present in standard SSH signatures. Relevant to the vault
only if the vault itself implements the FIDO2 authenticator interface.

---

## 2. Operations Requiring Private Key Access

### 2.1 Key Exchange -- Server Host Key Signature

**When:** Every SSH connection setup, during key exchange (KEX).

**Who signs:** The server, using its host private key.

**Purpose:** Proves to the client that the server possesses the private key
corresponding to the advertised host public key. This is SSH's server
authentication mechanism.

**What is signed:**

The server signs the exchange hash `H`. The hash `H` is computed over the
concatenation of the following fields (for standard DH per RFC 4253 section 8):

```
string    V_C        -- client's identification string (without CR LF)
string    V_S        -- server's identification string (without CR LF)
string    I_C        -- payload of the client's SSH_MSG_KEXINIT
string    I_S        -- payload of the server's SSH_MSG_KEXINIT
string    K_S        -- server's public host key blob
mpint     e          -- client's DH public value
mpint     f          -- server's DH public value
mpint     K          -- shared secret
```

The HASH function used to compute `H` depends on the key exchange method:

| KEX Method                            | HASH     | RFC      |
|---------------------------------------|----------|----------|
| `diffie-hellman-group1-sha1`          | SHA-1    | RFC 4253 |
| `diffie-hellman-group14-sha1`         | SHA-1    | RFC 4253 |
| `diffie-hellman-group14-sha256`       | SHA-256  | RFC 8268 |
| `diffie-hellman-group16-sha512`       | SHA-512  | RFC 8268 |
| `diffie-hellman-group18-sha512`       | SHA-512  | RFC 8268 |

For **DH Group Exchange** (RFC 4419), the hash input includes additional
fields for the negotiated group parameters:

```
string    V_C, V_S, I_C, I_S, K_S      -- same as above
uint32    min                            -- minimum group size requested
uint32    n                              -- preferred group size
uint32    max                            -- maximum group size
mpint     p                              -- safe prime
mpint     g                              -- generator
mpint     e, f, K                        -- same as above
```

| KEX Method                            | HASH     | RFC      |
|---------------------------------------|----------|----------|
| `diffie-hellman-group-exchange-sha1`  | SHA-1    | RFC 4419 |
| `diffie-hellman-group-exchange-sha256`| SHA-256  | RFC 4419 |

For **ECDH** (RFC 5656), the hash input uses the ECDH public keys:

```
string    V_C, V_S, I_C, I_S, K_S      -- same as above
string    Q_C                            -- client's ephemeral ECDH public key
string    Q_S                            -- server's ephemeral ECDH public key
mpint     K                              -- shared secret
```

| KEX Method                   | HASH     | RFC      |
|------------------------------|----------|----------|
| `ecdh-sha2-nistp256`         | SHA-256  | RFC 5656 |
| `ecdh-sha2-nistp384`         | SHA-384  | RFC 5656 |
| `ecdh-sha2-nistp521`         | SHA-512  | RFC 5656 |

For **Curve25519/Curve448** (RFC 8731), the exchange hash structure is
identical to ECDH above:

| KEX Method           | HASH     | RFC      |
|----------------------|----------|----------|
| `curve25519-sha256`  | SHA-256  | RFC 8731 |
| `curve448-sha512`    | SHA-512  | RFC 8731 |

**What comes out:** A signature blob in the format:

```
string    signature_algorithm_name       -- e.g. "rsa-sha2-256", "ssh-ed25519"
string    signature_blob                 -- algorithm-specific raw signature
```

**Vault operation:** `sign(host_private_key, H) -> signature`

The vault receives the pre-computed hash `H` (or the raw data to hash and
sign, depending on the algorithm). For RSA, the vault performs PKCS#1 v1.5
signing on the hash. For Ed25519, the vault must receive the raw data (not a
pre-hash) because Ed25519 hashes internally.

---

### 2.2 User Authentication -- Public Key Method (ssh-agent)

**When:** After key exchange, during the SSH_MSG_USERAUTH_REQUEST phase.

**Who signs:** The client, using its user private key (typically via ssh-agent).

**Purpose:** Proves the client possesses the private key corresponding to
the public key being offered for authentication.

**What is signed (RFC 4252 section 7):**

```
string    session_identifier             -- the exchange hash H from KEX
byte      SSH_MSG_USERAUTH_REQUEST       -- message type (50)
string    user_name                      -- username on the server
string    service_name                   -- typically "ssh-connection"
string    "publickey"                    -- method name
boolean   TRUE                           -- indicates signature is present
string    public_key_algorithm_name      -- e.g. "rsa-sha2-512"
string    public_key_blob                -- the user's public key
```

**What comes out:** A signature blob (same format as 2.1).

**SSH Agent Protocol (draft-ietf-sshm-ssh-agent):**

The ssh-agent receives an `SSH_AGENTC_SIGN_REQUEST`:

```
byte      SSH_AGENTC_SIGN_REQUEST        -- message type (13)
string    key_blob                       -- public key identifying which key to use
string    data                           -- the bytes to sign (the blob above)
uint32    flags                          -- signature algorithm selection
```

Flags for RSA key algorithm selection:

| Flag                       | Value | Meaning                    |
|----------------------------|-------|----------------------------|
| `SSH_AGENT_RSA_SHA2_256`   | 0x02  | Use `rsa-sha2-256`         |
| `SSH_AGENT_RSA_SHA2_512`   | 0x04  | Use `rsa-sha2-512`         |

The agent responds with `SSH_AGENT_SIGN_RESPONSE`:

```
byte      SSH_AGENT_SIGN_RESPONSE        -- message type (14)
string    signature                      -- the signature blob
```

**Vault operation:** `sign(user_private_key, data) -> signature`

This is the primary operation an ssh-agent-compatible vault must implement.
The vault receives arbitrary bytes (the authentication data blob) and a key
identifier, and returns a signature.

---

### 2.3 User Authentication -- Host-Based Method

**When:** During SSH_MSG_USERAUTH_REQUEST when using host-based authentication.

**Who signs:** The client host, using its host private key.

**Purpose:** Proves that the user is connecting from a trusted host.

**What is signed (RFC 4252 section 9):**

```
string    session_identifier
byte      SSH_MSG_USERAUTH_REQUEST
string    user_name                      -- remote username
string    service_name
string    "hostbased"                    -- method name
string    public_key_algorithm           -- for the client host key
string    public_key_and_certs           -- client host's public key blob
string    client_host_name               -- FQDN of the client host
string    client_user_name               -- local username on client host
```

**What comes out:** A signature blob.

**Vault operation:** `sign(client_host_private_key, data) -> signature`

This is structurally identical to user auth signing but uses the client
machine's host key instead of a user key.

---

### 2.4 Certificate Signing (OpenSSH Certificates)

**When:** Offline, using `ssh-keygen -s ca_key [-h] ...` or an equivalent API.

**Who signs:** The Certificate Authority (CA), using its CA private key.

**Purpose:** Creates an SSH certificate binding a public key to an identity,
with validity constraints.

#### 2.4.1 Certificate Types

| Type Value | Constant              | Purpose                   |
|------------|-----------------------|---------------------------|
| 1          | `SSH_CERT_TYPE_USER`  | User authentication       |
| 2          | `SSH_CERT_TYPE_HOST`  | Host authentication       |

#### 2.4.2 Certificate Key Type Identifiers

| Certificate Type                                  | Base Key Type              | Spec                          |
|---------------------------------------------------|----------------------------|-------------------------------|
| `ssh-rsa-cert-v01@openssh.com`                    | RSA                        | OpenSSH PROTOCOL.certkeys     |
| `ssh-dss-cert-v01@openssh.com`                    | DSA                        | OpenSSH PROTOCOL.certkeys     |
| `ecdsa-sha2-nistp256-cert-v01@openssh.com`        | ECDSA P-256                | OpenSSH PROTOCOL.certkeys     |
| `ecdsa-sha2-nistp384-cert-v01@openssh.com`        | ECDSA P-384                | OpenSSH PROTOCOL.certkeys     |
| `ecdsa-sha2-nistp521-cert-v01@openssh.com`        | ECDSA P-521                | OpenSSH PROTOCOL.certkeys     |
| `ssh-ed25519-cert-v01@openssh.com`                | Ed25519                    | OpenSSH PROTOCOL.certkeys     |
| `ssh-ed448-cert-v01@openssh.com`                  | Ed448                      | draft-miller-ssh-cert         |
| `sk-ecdsa-sha2-nistp256-cert-v01@openssh.com`     | FIDO ECDSA P-256           | OpenSSH PROTOCOL.u2f          |
| `sk-ssh-ed25519-cert-v01@openssh.com`             | FIDO Ed25519               | OpenSSH PROTOCOL.u2f          |

The IETF standardization effort (draft-miller-ssh-cert) defines equivalent
types without the `@openssh.com` suffix: `ssh-rsa-cert`, `ssh-dss-cert`,
`ecdsa-sha2-nistp256-cert`, `ssh-ed25519-cert`, `ssh-ed448-cert`.

#### 2.4.3 What Gets Signed (TBS Data)

The CA signs everything in the certificate structure **from the initial key
type string up to and including the `signature key` field**. The final
`signature` field is excluded (it is what the CA produces).

For an RSA certificate, the TBS data is:

```
string    "ssh-rsa-cert-v01@openssh.com"
string    nonce                          -- random bytes (>= 16 bytes)
mpint     e                              -- RSA public exponent
mpint     n                              -- RSA modulus
uint64    serial                         -- certificate serial number
uint32    type                           -- 1 (user) or 2 (host)
string    key_id                         -- human-readable identifier
string    valid_principals               -- packed list of allowed names
uint64    valid_after                    -- start of validity (Unix time)
uint64    valid_before                   -- end of validity (Unix time)
string    critical_options               -- constraints (e.g. force-command)
string    extensions                     -- permissions (e.g. permit-pty)
string    reserved                       -- empty for now
string    signature_key                  -- CA's public key blob
```

For Ed25519 certificates, replace the key-specific fields:

```
string    "ssh-ed25519-cert-v01@openssh.com"
string    nonce
string    pk                             -- 32-byte Ed25519 public key
uint64    serial
...                                      -- same metadata fields
string    signature_key
```

ECDSA and DSA certificates follow the same pattern with their respective
public key fields.

**What comes out:** The CA's signature over the TBS data, appended as the
final field:

```
string    signature                      -- signed using the CA's key type
```

The signature algorithm is determined by the **CA's key type**, not the
certificate's key type. An Ed25519 CA can sign RSA certificates, and vice
versa.

**Vault operation:** `sign(ca_private_key, tbs_data) -> signature`

The vault receives the serialized TBS bytes and produces a signature using
the CA's private key. The signature follows the same format as all other
SSH signatures (algorithm name + raw signature blob).

---

### 2.5 Key Exchange -- Ephemeral DH/ECDH Private Key Generation

**When:** Every SSH connection, during key exchange.

**Who:** Both client and server generate ephemeral key pairs.

**Purpose:** Produce the shared secret `K` for session key derivation.

This is listed for completeness. The ephemeral DH/ECDH private values are
**not** identity keys. They are generated fresh for each connection and
discarded after key exchange. A vault/HSM is typically not involved here
unless it provides an RNG or accelerated scalar multiplication.

| KEX Family                  | Ephemeral Operation                           | RFC      |
|-----------------------------|-----------------------------------------------|----------|
| DH (MODP groups)            | Generate random `x`; compute `e = g^x mod p`  | RFC 4253 |
| DH Group Exchange           | Same, with server-proposed `(p, g)`            | RFC 4419 |
| ECDH (NIST curves)          | Generate random `d`; compute `Q = d * G`       | RFC 5656 |
| Curve25519/Curve448          | Generate random scalar; compute `X25519`/`X448`| RFC 8731 |

**Vault relevance:** Low. These are session-scoped. However, if the vault is
the sole source of randomness or wants to enforce key quality, it could
generate the ephemeral private values.

---

## 3. Summary: Vault Signing Interface

All private key operations in SSH reduce to a single primitive:

```
sign(key_id, algorithm, data) -> signature_blob
```

The table below maps each SSH use case to this interface:

| Use Case                    | Who Holds the Key | Data to Sign                    | Algorithm Selected By       |
|-----------------------------|-------------------|---------------------------------|-----------------------------|
| Server host auth (KEX)      | Server            | Exchange hash `H`               | Host key type + negotiation |
| Client user auth            | User (ssh-agent)  | Auth data blob (session ID + USERAUTH_REQUEST fields) | Agent flags / negotiation |
| Client host-based auth      | Client host       | Auth data blob (session ID + USERAUTH_REQUEST fields) | Host key type + negotiation |
| Certificate signing (user)  | CA                | Certificate TBS data            | CA key type                 |
| Certificate signing (host)  | CA                | Certificate TBS data            | CA key type                 |

---

## 4. Signature Format Reference

Every SSH signature, regardless of context, uses the same wire encoding:

```
string    algorithm_name
string    signature_blob
```

The `signature_blob` internals vary by algorithm:

| Algorithm          | Signature Blob Contents                                       | Size         |
|--------------------|---------------------------------------------------------------|--------------|
| `ssh-rsa`          | RSASSA-PKCS1-v1_5(SHA-1, data) as unsigned big-endian integer | key modulus  |
| `rsa-sha2-256`     | RSASSA-PKCS1-v1_5(SHA-256, data) as unsigned big-endian integer| key modulus |
| `rsa-sha2-512`     | RSASSA-PKCS1-v1_5(SHA-512, data) as unsigned big-endian integer| key modulus |
| `ssh-dss`          | `r \|\| s` each as 160-bit unsigned big-endian integer         | 40 bytes     |
| `ecdsa-sha2-*`     | DER-like encoding of `(mpint r, mpint s)`                      | variable     |
| `ssh-ed25519`      | Raw Ed25519 signature per RFC 8032                            | 64 bytes     |
| `ssh-ed448`        | Raw Ed448 signature per RFC 8032                              | 114 bytes    |

### FIDO/U2F Signature Extensions

For `sk-*` key types, the signature blob includes additional FIDO fields:

```
string    algorithm_name                 -- e.g. "sk-ssh-ed25519@openssh.com"
string    inner_signature                -- standard signature bytes
byte      flags                          -- FIDO flags (user presence, etc.)
uint32    counter                        -- monotonic use counter
```

The FIDO authenticator signs a different structure than standard SSH:

```
bytes[32] SHA-256(application)           -- hash of the application ID (e.g. "ssh:")
byte      flags
uint32    counter
bytes[]   extensions                     -- FIDO extensions (if any)
bytes[32] SHA-256(message)               -- hash of the SSH data to authenticate
```

---

## 5. Algorithm-Specific Signing Considerations for Vault Implementations

### 5.1 RSA

- The vault receives pre-hashed data for KEX (the exchange hash `H` is
  already a hash), but for user auth it receives raw bytes that must be
  hashed as part of PKCS#1 v1.5 DigestInfo construction.
- The vault must support SHA-1 (legacy `ssh-rsa`), SHA-256 (`rsa-sha2-256`),
  and SHA-512 (`rsa-sha2-512`) with the same RSA key.
- Key sizes: RSA-2048 minimum (RFC 9142); RSA-3072 and RSA-4096 common.

### 5.2 ECDSA

- Standard ECDSA signing: hash the data with the curve's paired hash
  (SHA-256 for P-256, SHA-384 for P-384, SHA-512 for P-521), then sign.
- Requires a source of randomness for the nonce `k` (or use RFC 6979
  deterministic nonces for safety).
- The vault must output `(r, s)` as SSH mpints.

### 5.3 Ed25519

- Ed25519 is a "pure" signature scheme: the signing algorithm internally
  hashes the message with SHA-512. The vault **cannot** receive a pre-hash;
  it must receive the full message bytes.
- The private key seed is 32 bytes. The expanded private key (used
  internally) is 64 bytes.
- Signing is deterministic (no external randomness needed).

### 5.4 Ed448

- Similar to Ed25519 but uses SHAKE256 internally.
- Private key seed is 57 bytes. Signature is 114 bytes.
- Also deterministic.

### 5.5 DSA (Legacy)

- 1024-bit keys only, SHA-1 only. Deprecated everywhere.
- If supported, standard DSA signing with `(r, s)` output as 160-bit
  integers packed into a 40-byte blob.

---

## 6. Complete RFC Reference

| RFC/Spec                           | Defines                                                        |
|------------------------------------|----------------------------------------------------------------|
| RFC 4251                           | SSH protocol architecture, data type encoding                   |
| RFC 4252                           | SSH authentication protocol (publickey, hostbased methods)      |
| RFC 4253                           | SSH transport layer (KEX, host key signature, `ssh-rsa`, `ssh-dss`) |
| RFC 4419                           | DH group exchange (`diffie-hellman-group-exchange-sha256`)      |
| RFC 5656                           | ECDSA keys and ECDH key exchange for SSH                        |
| RFC 8268                           | Additional MODP DH groups (`group14-sha256` through `group18-sha512`) |
| RFC 8332                           | RSA with SHA-2 (`rsa-sha2-256`, `rsa-sha2-512`)                |
| RFC 8709                           | Ed25519 and Ed448 for SSH                                       |
| RFC 8731                           | Curve25519-sha256 and Curve448-sha512 key exchange              |
| RFC 8032                           | Edwards-curve Digital Signature Algorithm (Ed25519, Ed448)      |
| RFC 9142                           | KEX method recommendations and deprecations                     |
| draft-ietf-sshm-ssh-agent          | SSH agent protocol (`SSH_AGENTC_SIGN_REQUEST`)                  |
| draft-miller-ssh-cert              | SSH certificate format (IETF standardization track)             |
| OpenSSH PROTOCOL.certkeys          | OpenSSH certificate format (original specification)             |
| OpenSSH PROTOCOL.u2f               | FIDO/U2F key types for SSH (`sk-*` algorithms)                  |

---

## 7. Mapping to Vault Key Derivation

For integration with the BIP-32 key hierarchy described in
[Design.md](Design.md), the SSH protocol path would use:

- `prot'` = SSH protocol identifier
- `alg'` = one of: RSA, ECDSA, Ed25519, Ed448
- `param'` = key size (RSA) or curve (NIST P-256/P-384/P-521, Ed25519, Ed448)
- `role` = `host` (host key), `user` (user authentication key), `ca` (certificate authority key)

The vault exposes two levels of signing:

**Generic `SIGN` (function 2):** Produces a raw cryptographic signature with
no SSH framing. The caller is responsible for wrapping it in the SSH wire
format (`string algorithm_name, string signature_blob`).

```
result = vault.execute(FN_SIGN, data, key_path)
// result.data = raw signature bytes (64 bytes for Ed25519, etc.)
```

**Protocol-specific `SSH_SIGN` (function 16+):** Produces a complete SSH
signature blob including the algorithm name prefix, respecting agent flags
for RSA hash algorithm selection. Use this when the vault must handle
SSH-specific framing internally.

```
result = vault.execute(FN_SSH_SIGN, data, key_path)
// result.data = string(algorithm_name) + string(signature_blob)
```

In both cases:
- `key_path` identifies the key in the BIP-32 hierarchy
- `data` is the bytes to sign (exchange hash, auth blob, or certificate TBS)

For Ed25519, the vault must receive the full message bytes (not a pre-hash),
because Ed25519 hashes internally as part of its deterministic signing.
