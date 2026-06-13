# IZ KeyVault - Key Derivation Model

## Overview

IZ KeyVault uses a **hierarchical deterministic key derivation** model. From a single master seed,
all cryptographic keys for all protocols (SSH, Nostr, OpenPGP, Bitcoin) can be deterministically
regenerated. This means that backing up the master seed is sufficient to recover every key the system
has ever produced.

The derivation follows a four-level hierarchy:

```
Master Seed
  └── Identity Seed  (one per identity, e.g. alice@atlanta.com)
        └── Protocol Seed  (one per protocol: ssh, nostr, openpgp, bitcoin)
              └── Key Pair  (deterministically generated from protocol seed)
```

## Level 0: Master Seed

The master seed is the root of trust. It is a **BIP39 deterministic seed** — 32 bytes (256 bits) of
entropy, represented as a mnemonic word list.

### Generation

```
SecureRandom sr = new SecureRandom();       // system CSPRNG
DeterministicSeed masterSeed = DeterministicSeed.ofRandom(sr, 256, passphrase);
```

- Uses Java's `SecureRandom` (system entropy) for initial randomness
- Produces a BIP39 mnemonic (24 words) that encodes the seed
- The mnemonic is written to a file (default: `~/.config/iz-keyvault/master-seed`)

### Storage

The master seed file contains the raw mnemonic string:

```
parent skill hidden sponsor quality hurry idle alone worry bicycle proud reveal ...
```

This file should be backed up securely and then removed from the device.

### Class: `KeyVault`

```java
public class KeyVault {
    static final int SEED_SIZE = 32;       // 256 bits
    final DeterministicSeed seed;

    public static KeyVault fromRandomSeed();                           // new seed
    public static KeyVault fromSeedFile(File seedFile, String passphrase);  // restore
}
```

## Level 1: Sub Seed

Before creating identities, a **sub seed** is derived from the master seed. This sub seed is stored
on the device and used for day-to-day operations, so the master seed does not need to remain present.

### Derivation

The derivation string is `"sub-seed-{count}"` where `count` is a CLI parameter (default: `0`):

```
subSeed = SHA-256(masterSeed.seedBytes || mangle("sub-seed-" + count))
```

The `--count` parameter allows generating **multiple independent sub seeds** from the same master
seed. Each count value produces a completely different sub seed and therefore a completely different
set of identities and keys:

```
count=0  →  "sub-seed-0"  →  sub seed A  →  identity keys A
count=1  →  "sub-seed-1"  →  sub seed B  →  identity keys B
count=2  →  "sub-seed-2"  →  sub seed C  →  identity keys C
```

The count serves as a **key rotation mechanism**. If a sub seed is feared compromised, the user
generates a new sub seed by incrementing the count. This derives an entirely new key hierarchy
from the same master seed, effectively rotating all keys without needing a new master seed.

### CLI Usage

```bash
iz-keyvault sub-seed create --master-seed-file /tmp/master-seed --count 0   # initial sub seed
iz-keyvault sub-seed create --master-seed-file /tmp/master-seed --count 1   # rotation after compromise
```

### Implementation

The derivation uses `WalletHelper.createSubSeed()`:

```java
public static DeterministicSeed createSubSeed(DeterministicSeed seed, String string, String passphrase) {
    return createSubSeed(seed, mangle(string), passphrase);
}

public static DeterministicSeed createSubSeed(DeterministicSeed seed, byte[] hash, String passphrase) {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(seed.getSeedBytes());
    md.update(hash);
    return DeterministicSeed.ofEntropy(md.digest(), passphrase);
}
```

### The `mangle()` function

The `mangle()` function normalizes input strings for the derivation:

- If the string is **32 bytes or shorter**: use the raw bytes directly
- If the string is **longer than 32 bytes**: hash it with SHA-256

```java
public static byte[] mangle(String string) {
    if (string.getBytes().length <= 32)
        return string.getBytes();

    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(string.getBytes(StandardCharsets.UTF_8));
    return md.digest();
}
```

This ensures the derivation input is always a compact, fixed-size value for long strings, while
preserving short strings as-is for readability in the derivation chain.

### Storage

The sub seed is persisted as a BIP39 mnemonic file at `~/.config/iz-keyvault/seed`.

## Level 2: Identity Seed

Each identity (e.g. `alice@atlanta.com`) gets its own deterministic sub-seed derived from the
sub seed.

### Derivation

```
identitySeed = SHA-256(subSeed.seedBytes || mangle(identityId))
```

Where `identityId` is a string like `"alice@atlanta.com"`.

### Class: `Identity`

```java
public class Identity {
    final String name;
    final String id;
    public final DeterministicSeed seed;

    public Identity(KeyVault keyVault, String id, String name) {
        this.id = id;
        this.seed = WalletHelper.createSubSeed(keyVault.seed, id, "");
        this.name = name;
    }
}
```

### Storage

Identity metadata is stored at `~/.config/iz-keyvault/{identityId}/.metadata.json`:

```json
{ "name": "Alice" }
```

A `default` symlink points to the active identity.

## Level 3: Protocol Seed

Each protocol (SSH, Nostr, OpenPGP, Bitcoin) derives its own seed from the identity seed.

### Derivation

```
protocolSeed = SHA-256(identitySeed.seedBytes || mangle(protocolName))
```

Where `protocolName` is one of: `"ssh"`, `"nostr"`, `"openpgp"`, `"bitcoin"`.

### Class: `AbstractProtocol`

```java
abstract public class AbstractProtocol {
    protected final DeterministicSeed seed;
    protected final SecureRandom sr;

    protected AbstractProtocol(Identity identity) {
        String pmd = getProtocolName();
        this.seed = WalletHelper.createSubSeed(identity.seed, pmd, "");
        this.sr = WalletHelper.getDeterministicSecureRandomFromSeed(seed);
    }
}
```

The protocol seed is immediately converted into a **deterministic SecureRandom** (see next section).

## Level 4: Key Pair Generation

The final step converts the protocol seed into actual cryptographic key pairs using a
**deterministic CSPRNG**.

### ChaCha20SecureRandom

The protocol seed bytes are used to initialize a **ChaCha20-based CSPRNG**:

```java
public static SecureRandom getDeterministicSecureRandomFromSeed(DeterministicSeed seed) {
    byte[] seedBytes = seed.getSeedBytes();
    return new ChaCha20SecureRandom(seedBytes);
}
```

`ChaCha20SecureRandom` works as follows:

1. **Key derivation**: `key = SHA-256(seedBytes)` (32 bytes / 256 bits)
2. **Nonce**: first 8 bytes of `seedBytes`
3. **Stream generation**: ChaCha20 stream cipher (BouncyCastle `ChaChaEngine`) initialized with the
   derived key and nonce
4. Each call to `nextBytes()` produces the next block(s) from the ChaCha20 stream

```java
public class ChaCha20SecureRandom extends SecureRandom {
    public ChaCha20SecureRandom(byte[] seed) {
        // key = SHA-256(seed)
        SHA256Digest sha256 = new SHA256Digest();
        sha256.update(seed, 0, seed.length);
        sha256.doFinal(key, 0);

        // nonce = seed[0..7]
        System.arraycopy(seed, 0, nonce, 0, NONCE_SIZE);

        // Initialize ChaCha20 engine
        chaCha20Engine = new ChaChaEngine();
        chaCha20Engine.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
    }
}
```

This CSPRNG is **fully deterministic** — the same seed always produces the same byte stream, which
means the same `KeyPairGenerator` will always produce the same sequence of key pairs.

### KeyPairGenerator Initialization

The deterministic `SecureRandom` is passed to Java's `KeyPairGenerator`:

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithmName);
kpg.initialize(keySize, deterministicSecureRandom);
KeyPair kp = kpg.generateKeyPair();
```

The algorithm and key size depend on the protocol:

| Protocol | Algorithm            | Key Size | Java KeyPairGenerator     |
|----------|----------------------|----------|---------------------------|
| SSH      | Ed25519 (default)    | 255 bits | `Ed25519`                 |
| SSH      | RSA (optional)       | 2048+    | `RSA`                     |
| Nostr    | secp256k1 ECDSA      | 256 bits | `ECDSA` (BouncyCastle BC) |
| OpenPGP  | RSA                  | 2048+    | `RSA`                     |
| Bitcoin  | secp256k1 (bitcoinj) | 256 bits | BIP32 DeterministicKey    |

### Fingerprint Calculation

After generating a key pair, a **fingerprint** is calculated. This fingerprint is protocol-specific
and serves as a compact identifier for the key:

| Protocol | Fingerprint Algorithm                                     |
|----------|-----------------------------------------------------------|
| SSH      | `SHA-256(OpenSSH-encoded-public-key)`                     |
| Nostr    | Raw 32-byte Schnorr public key (derived from private key) |
| OpenPGP  | PGP v4 fingerprint (BouncyCastle `BcPGPKeyPair`)          |
| Bitcoin  | `RIPEMD-160(SHA-256(public-key))` (pubKeyHash)            |

The fingerprint is stored in the credentials metadata file. It is crucial for key restoration.

## Key Restoration

Keys are never stored directly. Instead, only the **fingerprint** and **metadata** are persisted.
To restore a key, the system:

1. Loads the metadata (including fingerprint) from `defaultCredentials.json`
2. Recreates the deterministic `SecureRandom` from the same seed chain
3. Generates key pairs sequentially until one matches the stored fingerprint
4. Returns the matching key pair

```java
private KeyPair restoreKey(KeyPairGenerator kpg, long maxTries) {
    for (int i = 0; i < maxTries; i++) {
        KeyPair candidate = kpg.genKeyPair();
        byte[] calculatedFingerprint = calculateFingerPrint(candidate);

        if (Arrays.equals(metaData.fingerprint, calculatedFingerprint)) {
            return candidate;  // Key restored
        }
    }
    throw new RuntimeException("No key found");
}
```

- Maximum attempts: **1000** (`KEY_RESTORE_MAX_TRIES`)
- In practice, the first generated key should match (attempt 0), since the deterministic CSPRNG
  produces the same sequence every time
- The retry mechanism handles edge cases where multiple credentials were created under the same
  protocol seed (the Nth key will be found at attempt N)

## Complete Derivation Chain

Here is the full derivation chain from master seed to a specific key:

```
1. Master Seed (32 bytes, BIP39 mnemonic, system entropy)
       |
       | SHA-256(masterSeedBytes || mangle("sub-seed-{count}"))
       v
2. Sub Seed (32 bytes, BIP39, stored on device)
       |
       | SHA-256(subSeedBytes || mangle("alice@atlanta.com"))
       v
3. Identity Seed (32 bytes, in-memory only)
       |
       | SHA-256(identitySeedBytes || mangle("ssh"))
       v
4. Protocol Seed (32 bytes, in-memory only)
       |
       | ChaCha20SecureRandom:
       |   key   = SHA-256(protocolSeedBytes)
       |   nonce = protocolSeedBytes[0..7]
       v
5. Deterministic CSPRNG (infinite byte stream)
       |
       | KeyPairGenerator.initialize(algSize, csprng)
       | KeyPairGenerator.generateKeyPair()
       v
6. Key Pair (e.g. Ed25519 for SSH)
       |
       | Protocol-specific fingerprint calculation
       v
7. Fingerprint (persisted to defaultCredentials.json)
```

## Vault Directory Structure

```
~/.config/iz-keyvault/
├── master-seed                               # BIP39 mnemonic (back up, then remove)
├── seed                                      # Sub seed mnemonic (stays on device)
├── default -> alice@atlanta.com/             # Symlink to active identity
└── alice@atlanta.com/
    ├── .metadata.json                        # {"name": "Alice"}
    ├── ssh/
    │   └── defaultCredentials.json           # SshMetaData + fingerprint
    ├── nostr/
    │   └── defaultCredentials.json           # NostrMetaData + fingerprint
    └── openpgp/
        └── defaultCredentials.json           # OpenPGPMetaData + fingerprint + creationTime
```

### Example: SSH Credentials File

```json
{
  "publicKeyMetadata": {
    "pubAlg": "ed25519",
    "pubBits": 255
  },
  "fingerprint": "<base64-encoded SHA-256 of OpenSSH public key>"
}
```

## Security Properties

1. **Deterministic**: The same master seed always produces the same keys for the same identity and
   protocol. No randomness is involved after the initial seed generation.

2. **Hierarchical isolation**: Knowing a protocol seed does not reveal the identity seed, the sub
   seed, or the master seed (SHA-256 is one-way).

3. **No private key storage**: Private keys are never written to disk. Only fingerprints and metadata
   are persisted. Keys are regenerated on demand from the seed.

4. **Single backup**: The master seed mnemonic is the only thing that needs to be backed up. From it,
   all sub seeds, identities, and keys can be regenerated.

5. **Forward derivation only**: Each level can only derive its children, not its parents or siblings.
   Compromising an identity seed does not compromise other identities.