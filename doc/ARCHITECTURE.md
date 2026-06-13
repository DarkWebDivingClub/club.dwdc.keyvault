# DWDC Key System Architecture

Status: Draft

This document defines the current architectural direction for KeyMaster,
Avatar, Avatar services, and KeyVault. Earlier design documents are archived
under [old/](old/).

## Goals

The system must:

- keep mnemonic phrases, derived private seeds, and private keys inside the
  KeyMaster and KeyVault security boundary;
- support protocol-specific operations without coupling KeyVault to external
  protocols;
- let a KeyMaster serve applications running on another host;
- support user authentication and approval before sensitive operations;
- expose native host interfaces such as SSH agent, GnuPG, and PKCS#11;
- allow transports and host adapters to evolve independently.

## Components

```text
Target host                                      Controller host or device

Application
    |
Native protocol
    |
Avatar service
    |
Uniform local Avatar API
    |
Avatar
    |
Authenticated Avatar-KeyMaster protocol
    |
KeyMaster
    |
Protocol-specific KeyMaster service
    |
KeyVault
```

### KeyMaster

KeyMaster is the controller and security authority.

KeyMaster:

- owns identities, accounts, key metadata, configuration, and policy;
- records which protocol configurations and derived keys are active for each
  identity;
- implements protocol-specific services;
- determines which services and keys a caller may use;
- requests user authentication or explicit approval when policy requires it;
- manages sessions and delegated capabilities;
- translates protocol operations into constrained KeyVault calls;
- returns public information, signatures, decrypted data, or other operation
  results;
- records security-relevant audit information.

KeyMaster must not give Avatar unrestricted KeyVault access. In particular,
Avatar must not receive mnemonic phrases, BIP-39 passphrases, private seeds,
private keys, or an unrestricted key-derivation function.

Examples of KeyMaster services include:

- SSH service;
- OpenPGP service;
- Nostr service;
- TLS and X.509 service;
- Bitcoin service.

Each service defines its own versioned operations and data types. For example,
the SSH service may expose public-key lookup and SSH signing, while the Nostr
service may expose public-key lookup, event signing, and NIP-44
encryption/decryption.

The initial protocol-specific service contracts are:

- [SSH service protocol](SSH.md)
- [PKCS#11 service protocol](PKCS11.md)

### KeyVault

KeyVault is the deterministic cryptographic engine.

KeyVault:

- derives keys from the configured root secret;
- executes narrowly defined cryptographic operations;
- has no user interface, network listener, or host integration;
- does not make authorization decisions;
- does not expose private key material unless an explicitly enabled
  administrative operation requires it.

KeyMaster is responsible for converting semantic requests into KeyVault paths
and function calls.

### Avatar

Avatar is KeyMaster's representative on a target host.

Avatar:

- attaches to and authenticates a KeyMaster;
- negotiates available services and capabilities;
- maintains encrypted sessions with KeyMaster;
- manages the lifecycle of Avatar services on the host;
- provides a uniform local API to Avatar services;
- routes requests and responses;
- handles reconnects, timeouts, cancellation, and session revocation;
- exposes no private key material.

Avatar is not the policy authority and should not implement protocol
cryptography that belongs in KeyMaster. It may enforce local restrictions, but
KeyMaster performs the final authorization.

### Avatar Services

An Avatar service integrates one native host protocol with Avatar.

An Avatar service:

- exposes the socket, shared library, or operating-system interface expected by
  local applications;
- implements protocol-specific session and object behavior;
- translates native requests into the uniform local Avatar API;
- translates KeyMaster results back into the native protocol;
- requests only the capabilities needed for its protocol.

Avatar services should normally run separately from the Avatar daemon. This
keeps native protocol parsers isolated and lets services be installed,
restarted, or upgraded independently.

Initial Avatar service candidates are:

| Avatar service | Native interface | Typical clients |
|---|---|---|
| SSH agent | SSH-agent Unix socket | OpenSSH, Git |
| PKCS#11 | PKCS#11 shared library | Firefox, Brave, TLS applications |
| GnuPG | GPG-agent/scdaemon integration | GnuPG |
| Local CLI | Command-line client | Administration and diagnostics |

The PKCS#11 adapter is expected to be a thin shared library that connects to
Avatar's local API. It must not contain or derive private keys.

GnuPG integration remains an open design decision. It may use a PKCS#11 bridge
where compatible, or a dedicated GPG/Assuan adapter when OpenPGP behavior
cannot be represented correctly through PKCS#11.

## Interfaces

### Avatar Service to Avatar

Avatar exposes one uniform local API, preferably over a user-scoped Unix-domain
socket on Unix systems.

The local API is capability-oriented rather than tied to SSH, GnuPG, or
PKCS#11. Candidate operations include:

```text
session.open
session.close
capabilities.list
identities.list
keys.list
key.describe
key.public
certificate.get
certificate.chain
sign
decrypt
deriveSecret
request.status
request.cancel
```

An Avatar service identifies its adapter type and requests a limited capability
set when opening a session. For example:

```json
{
  "adapter": "ssh-agent",
  "requestedCapabilities": [
    "keys.list:ssh",
    "key.public:ssh",
    "sign:ssh"
  ]
}
```

The local API must support request identifiers, structured errors, operation
timeouts, cancellation, and asynchronous approval states.

### Avatar to KeyMaster

Avatar and KeyMaster communicate using an authenticated, encrypted, versioned
protocol.

The current transport candidate is Nostr with NIP-44 encryption. The service
model must remain independent of Nostr so that another transport can implement
the same protocol.

The protocol must support:

- attachment and mutual authentication;
- protocol and service version negotiation;
- service discovery;
- scoped service-channel creation;
- identity and capability restrictions;
- request/response correlation;
- pending approval responses;
- cancellation, expiry, detach, and revocation;
- reconnect and session recovery rules;
- explicit message-size and replay limits.

Avatar sends requests to a named, versioned KeyMaster service. It does not send
arbitrary Java method names or unrestricted KeyVault paths.

### KeyMaster to KeyVault

The KeyMaster-to-KeyVault boundary is a narrow execution API:

```text
execute(function, keyPath, parameters, payload) -> result
```

This boundary may initially be in-process. Its contract must permit a future
isolated process, hardware module, smart card, or other secure execution
environment.

## Service and Key Addressing

KeyMaster owns stable identifiers for:

- identities;
- services;
- configurations;
- keys;
- certificates;
- sessions.

A conceptual service address is:

```text
identity / service / configuration / key-role / key-index
```

External callers receive opaque identifiers rather than raw KeyVault
derivation paths. KeyMaster resolves those identifiers and applies policy
before invoking KeyVault.

## Identity Configuration and Key Activation

The seed defines which keys KeyVault can derive. It does not define which keys
KeyMaster exposes or permits callers to use.

KeyMaster maintains metadata for every configured identity. The metadata
records:

- the identity identifier and display metadata;
- the protocol services assigned to the identity;
- the algorithm, key role, and key index assigned to each service;
- whether each service and key assignment is active;
- protocol-specific public metadata, such as certificates or OpenPGP user IDs;
- authorization policy and allowed Avatars;
- configuration version, creation time, and modification time.

All supported protocol derivation namespaces may be technically available
from a seed, but no protocol or key becomes active merely because it can be
derived. KeyMaster services list and use only assignments marked active.
Disabling an assignment prevents new operations without changing the seed or
destroying the deterministic ability to derive the same key later.

When creating an identity, the user selects which protocols to assign to it.
For example, an identity may enable SSH and Nostr while leaving PKCS#11,
OpenPGP, and Bitcoin inactive. Each assignment selects its algorithm, key
role, key index, metadata, and policy.

Identity templates may provide reusable defaults. A template can define:

- a set of protocol assignments;
- default algorithms and key roles;
- default key indices or allocation rules;
- required protocol metadata;
- default authorization and approval policy.

Applying a template creates ordinary identity configuration records. The
identity may then override, activate, or deactivate individual assignments.
Templates do not contain seeds or private keys.

### Metadata Persistence with Nostr

KeyMaster may store and synchronize identity configuration metadata as signed,
encrypted Nostr events. This gives KeyMaster a transport-independent place to
recover configuration from one or more relays.

The persisted records must:

- be signed by an administrative KeyMaster identity;
- be encrypted for the intended KeyMaster installation or owner;
- contain stable identity, assignment, and configuration identifiers;
- include a monotonically ordered revision or an explicit predecessor;
- support revocation and tombstone records;
- exclude mnemonic phrases, seed material, private keys, and secret
  passphrases.

The Nostr relay is storage and synchronization infrastructure, not the
authority that activates keys. KeyMaster verifies signatures, encryption,
ownership, revision ordering, and policy before accepting metadata. Cached
local state remains necessary when relays are unavailable.

## Authorization and User Interaction

Authorization is part of KeyMaster, not an Avatar service.

For each operation, KeyMaster evaluates:

- authenticated caller and Avatar session;
- requested service and capability;
- identity and key scope;
- operation type and algorithm;
- configured policy;
- request origin and contextual information;
- whether user authentication or approval is required.

An operation may complete immediately, be rejected, or enter a pending state:

```text
requested -> pending-approval -> approved -> completed
                              \-> rejected
                              \-> expired
                              \-> cancelled
```

A Kotlin or Android GUI is a KeyMaster user interface. It consumes pending
authorization requests, presents them to the user, performs platform
authentication where configured, and returns the decision to KeyMaster. The
GUI must call the same KeyMaster application API used by non-graphical
frontends; cryptographic policy must not be implemented in Compose screens.

## Example Flows

### SSH Signing

```text
ssh
 -> SSH-agent socket
 -> SSH Avatar service
 -> Avatar local API: sign
 -> Avatar-KeyMaster SSH service request
 -> KeyMaster policy and optional approval
 -> KeyVault signing operation
 -> SSH signature response
```

### Browser Client Certificate

```text
Firefox or Brave
 -> libdwdc-pkcs11
 -> PKCS#11 Avatar service
 -> Avatar local API: certificate.get or sign
 -> Avatar-KeyMaster TLS/X.509 service request
 -> KeyMaster policy and optional approval
 -> KeyVault signing operation
 -> PKCS#11 result
```

### OpenPGP Signing

```text
gpg
 -> GnuPG adapter or validated PKCS#11 bridge
 -> Avatar local API: sign
 -> Avatar-KeyMaster OpenPGP service request
 -> KeyMaster policy and optional approval
 -> KeyVault signing operation
 -> OpenPGP-compatible signature result
```

Public OpenPGP certificates, fingerprints, subkey metadata, and creation times
remain first-class metadata. KeyExporter may construct exportable OpenPGP key
rings, while runtime private-key operations remain controlled by KeyMaster.

## Security Boundaries

The architecture establishes these boundaries:

1. Applications trust their native adapter interface.
2. Avatar services authenticate to the local Avatar API and receive limited
   capabilities.
3. Avatar authenticates to KeyMaster and receives only explicitly delegated
   services.
4. KeyMaster performs authorization and user interaction.
5. KeyVault performs constrained cryptographic operations.

Compromise of an Avatar or Avatar service must not reveal root secrets or
private key material. KeyMaster must be able to revoke an Avatar, an adapter
session, a service channel, or an individual capability.

## Decisions Still Required

The following require separate architecture decision records:

1. Local Avatar API framing, authentication, and operating-system support.
2. Final Avatar-KeyMaster message schema and service versioning.
3. Nostr event kinds, replay protection, and reconnect behavior.
4. GnuPG integration through PKCS#11 versus a dedicated Assuan adapter.
5. PKCS#11 object model, token model, and certificate provisioning.
6. KeyMaster process model on desktop, server, and Android.
7. User approval lifecycle and GUI notification mechanism.
8. Audit-log format, retention, and privacy policy.
9. Service plug-in discovery and compatibility rules.

These decisions should be recorded as versioned architecture decision records
under `doc/adr/`.
