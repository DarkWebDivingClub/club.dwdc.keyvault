# IZ KeyVault - Architecture

This document describes the system architecture of IZ KeyVault. For key derivation
details (seed hierarchy, ChaCha20 CSPRNG, fingerprint restoration), see
[KEY_DERIVATION.md](KEY_DERIVATION.md).

## Overview

The system is split into three components:

```
┌────────────────┐     ┌──────────────┐     ┌──────────────┐
│    KeyVault    │     │  KeyMaster   │     │    Avatar    │
│  crypto engine │◄────│  orchestrator│◄────│   gateway    │
│                │     │              │     │              │
│ deterministic  │     │ services,    │     │ Nostr/UDP    │
│ key ops only   │     │ identity,    │     │ relay for    │
│                │     │ routing      │     │ remote access│
└────────────────┘     └──────────────┘     └──────────────┘
```

**KeyVault** is the crypto engine. It takes a key path and a call configuration, and returns
bytes. It has no knowledge of services, identities, or protocols as concepts — only as opaque
byte arrays fed into the derivation chain.

**KeyMaster** is the service orchestrator. It owns the semantic model: identities, protocols,
configurations. It presents a hierarchical service tree where each node is addressable via a
path like `["alice@atlanta.com", "ssh", "<config-hash>"]`.

**Avatar** is the gateway. It sits between untrusted clients and KeyMaster, relaying
requests over Nostr-encrypted UDP. A phone can talk to a KeyMaster running on a home server
without either knowing each other's network address.

## KeyVault — The Crypto Engine

KeyVault has a single entry point:

```java
public byte[] execute(KeyPath keyPath, AbstractCallConfig callConfig)
```

`KeyPath` is a record of three byte arrays:

```java
public record KeyPath(byte[] identity, byte[] protocol, byte[] config) {}
```

These three fields are fed into a three-level seed derivation chain (each level is
`SHA-256(parentSeed || bytes)`), producing a protocol-specific seed. KeyVault does not
interpret these bytes — it just derives from them.

`AbstractCallConfig` carries a `callId` integer that selects which operation to perform, plus
operation-specific parameters (public key to match, data to sign, etc.). The `callId` is used
to look up a call executor class from a static dispatch map:

| Range     | Protocol | Operations                              |
|-----------|----------|-----------------------------------------|
| `0x3000+` | SSH      | getPublicKey, sign                      |
| `0x4000+` | Nostr    | getPublicKey, signEvent, nip44Encrypt/Decrypt |
| `0x5000+` | Bitcoin  | getWatchingKey, sign                    |

Each call executor is an inner class of KeyVault that extends `AbstractKeyVaultCall`. It
receives the derived seed in its constructor and implements `execute()` to perform the
cryptographic operation. The executor is instantiated via reflection from the dispatch map:

```java
callMap.get(callConfig.callId)
    .getDeclaredConstructor(KeyVault.class, KeyPath.class, callConfig.getClass())
    .newInstance(this, keyPath, callConfig);
```

KeyVault is stateless per call. The same `(KeyPath, CallConfig)` always produces the same
`byte[]`.

**Key source:** `KeyVault.java`

## The KeyMaster-KeyVault Boundary

KeyMaster does not call `KeyVault.execute()` directly. Between them sits `KeyVaultRunnable`,
a serialization point built on `BlockingQueue`:

```
KeyMaster threads                KeyVaultRunnable thread
      │                                 │
      ├─ executeTask(path, config) ──►  │
      │   (creates KeyVaultTask,        │
      │    puts on task queue,     tasks.take()
      │    blocks on result queue)      │
      │                           keyVault.execute(...)
      │                                 │
      │  ◄── result bytes ─────── result.put(bytes)
      │                                 │
```

`KeyVaultRunnable` runs in its own thread, started by `KeyMasterStackedService` at
construction time. Multiple KeyMaster threads can submit tasks concurrently; the
`BlockingQueue` serializes them into single-threaded execution on the vault side. Each task
carries its own single-slot `BlockingQueue<byte[]>` for the return value — the caller blocks
on `task.result.take()` until the vault thread puts the result.

This boundary is **transport-agnostic**. Today it is an in-process `BlockingQueue`. It could
be a socket, a USB channel to a hardware device, or an ISO 7816 APDU exchange with a smart
card — the interface is the same: send `(KeyPath, CallConfig)`, receive `byte[]`.

**Key sources:** `KeyVaultRunnable.java`, `KeyMasterStackedService.java`

## KeyVaultProxy — Bridging Semantics to Bytes

`KeyVaultProxy` sits on the KeyMaster side and translates typed, protocol-aware calls into
the `(KeyPath, CallConfig) → byte[]` interface that KeyVault expects.

It contains three inner classes — `BitcoinProtocolExecutor`, `SshProtocolExecutor`,
`NostrProtocolExecutor` — each constructed with a protocol-specific configuration object.
On construction, the executor assembles a `KeyPath` by mangling the identity string, the
protocol ID, and the JSON-serialized configuration:

```java
this.keyPath = new KeyVault.KeyPath(
    WalletHelper.mangle(identity.id),
    WalletHelper.mangle(SshProtocolStackedService.PROTOCOL_ID),
    WalletHelper.mangle(ConfigurationHelper.toJSON(config)));
```

When a method like `sign()` is called, the executor constructs the appropriate `CallConfig`
and submits it through `KeyVaultRunnable.executeTask()`.

**Key source:** `KeyVaultProxy.java`

## The Addressing Scheme

Every entity in the system is addressed by a path of three components:

```
identity  /  protocol  /  configuration
```

For example: `alice@atlanta.com / ssh / {"type":"ED25519","size":255}`.

At the KeyVault level, these are three opaque `byte[]` values in a `KeyPath`. KeyVault
derives a seed from them but does not parse them. The `mangle()` function normalizes each
component: strings of 32 bytes or less are used as-is; longer strings are SHA-256 hashed.
This means the configuration (which is typically a JSON string longer than 32 bytes) becomes
a hash, while short values like `"ssh"` pass through unchanged.

KeyMaster owns the semantics. It knows that `"alice@atlanta.com"` is an identity, that
`"ssh"` maps to `SshProtocolStackedService`, and that the configuration determines key
parameters. The same addressing scheme drives both the seed derivation (in KeyVault) and the
service routing (in the stacked service tree).

## The Secure Service Stack

The service layer is a tree of `StackedService` nodes. Each node can process a JSON-RPC
message locally or delegate to a child by stripping the first element from an address path.

### Core classes

**`IStackedService`** — interface exposing `getDefaultId()` and `getChildIds()`.

**`StackedService`** — holds a map of child `StackedSubService` instances and a
`ServiceProcessor`. The `process()` method implements address-based routing:

```java
public String process(List<String> address, String message) {
    if (address.isEmpty())
        return processor.process(message);          // handle locally
    return subServices.get(address.removeFirst())   // delegate to child
        .process(address, message);
}
```

**`StackedSubService<A extends StackedService>`** — a service that has a typed parent.
Self-registers with the parent on construction:

```java
public StackedSubService(A parent, String id) {
    this.parent = parent;
    if (parent != null)
        parent.subServices.put(id, this);
}
```

### Service tree

```
KeyMasterStackedService
  └─ IdentityStackedService ["alice@atlanta.com"]
       ├─ BitcoinProtocolStackedService ["bitcoin"]
       │    └─ BitcoinConfigurationStackedService [<config-hash>]
       ├─ SshProtocolStackedService ["ssh"]
       │    └─ SshConfigurationStackedService [<config-hash>]
       └─ NostrProtocolStackedService ["nostr"]
            └─ NostrConfigurationStackedService [<config-hash>]
```

A request to `["alice@atlanta.com", "bitcoin", "<config-hash>"]` with message
`{"methodName":"sign","args":[...]}` gets routed through three levels to the configuration
service, where `ServiceProcessor` handles it.

### JSON-RPC dispatch

**`ServiceProcessor<S>`** deserializes an incoming JSON message into a `CallRequestMessage`
(id, methodName, args), finds the matching method on the service object by name via
reflection, deserializes arguments to the target parameter types, invokes the method, and
returns a `CallResponseMessage` (id, result).

**`ServiceInvocationHandler<A>`** is the client-side counterpart. It implements
`InvocationHandler` to create dynamic proxies: calling a method on the proxy serializes the
call as a `CallRequestMessage`, sends it via `AvatarConnector.sendText()`, and deserializes
the `CallResponseMessage` back into the return type.

The `recast()` helper handles type conversion across the JSON boundary:

```java
static Object recast(Object parameter, Class<?> type) {
    return mapper.readValue(mapper.writeValueAsString(parameter), type);
}
```

**Key sources:** `IStackedService.java`, `StackedService.java`, `StackedSubService.java`,
`ServiceProcessor.java`, `ServiceInvocationHandler.java`

## Avatar — The Gateway

Avatar (`IZSystemAvatar3`) bridges untrusted clients to KeyMaster over Nostr-encrypted UDP.
It runs two concurrent services:

**DownLinkService** — listens on `lowerSocket` for client requests. When a request arrives,
it records the route (sender pubkey, event ID, socket address) in a correlation map keyed by
request ID, then forwards the request to KeyMaster via the `upperSocket`.

**UpLinkService** — listens on `upperSocket` for KeyMaster responses. When a response
arrives, it looks up the original client route from the correlation map and sends the response
back to the client via `lowerSocket`.

```
Client                  Avatar                   KeyMaster
  │                       │                         │
  ├─ Request(id=42) ──►   │                         │
  │                  paths[42] = client route        │
  │                       ├─ Request(id=42) ──────►  │
  │                       │                          │
  │                       │  ◄── Response(id=42) ────┤
  │                  route = paths.remove(42)        │
  │  ◄── Response(id=42) ─┤                         │
```

Messages are Nostr events, encrypted with NIP-44 (ChaCha20-Poly1305). `LinkService` handles
the receive loop: it receives a `GenericEvent` from the UDP socket, determines the encryption
type from event tags, decrypts the content, and dispatches to `onRequest()` or `onResponse()`
based on whether the event carries a response tag.

`AvatarConnector` is the client-side complement. It manages a `Transaction` map for
request-response correlation. `sendText()` creates a `Request`, registers a `Transaction`
(which contains a `BlockingQueue<Response>`), sends the request, and blocks on the response
queue until the avatar delivers the reply.

**Key source:** `IZSystemAvatar3.java`, `AvatarConnector.java`

## Smart Card Compatibility

The KeyVault interface — `(KeyPath, CallConfig) → byte[]` — was designed to map onto the
ISO 7816 APDU command structure used by smart cards:

| KeyVault concept   | APDU equivalent          |
|--------------------|--------------------------|
| `callId`           | INS byte (instruction)   |
| `KeyPath` bytes    | Command data field       |
| `CallConfig` fields| Command data / P1-P2     |
| `byte[]` return    | Response data + SW1/SW2  |

The split is: **KeyVault operations stay on the card**, everything else stays on the host.
The card holds the seed and executes `AbstractKeyVaultCall` subclasses. The host runs
KeyMaster, the service tree, and the avatar layer. The `KeyVaultRunnable` boundary becomes
the card reader interface — same `(KeyPath, CallConfig) → byte[]` contract, different
transport.

What this means in practice:

- The card never sees identity strings, protocol names, or configuration JSON — only mangled
  byte arrays
- The card never parses JSON-RPC or routes service requests
- The card's interface is a small, fixed set of call IDs (getPublicKey, sign, encrypt,
  decrypt per protocol) — easy to audit, easy to certify
- Key material never leaves the card; only public keys and signatures come back

## Design Philosophy

**Butler, not a nanny.** The system does not enforce a security policy. It provides key
management as a service. If the user wants to export a private key, the system helps. If the
user wants signing-as-a-service without ever exposing the key, the system supports that too.
The README puts it as "your keys, your money, your responsibility."

**Key export coexists with delegation.** The same KeyVault can serve key material to the
local CLI (for export into `~/.ssh/`) and to remote clients (via Avatar, where the key never
leaves the vault). The architecture does not privilege one mode over the other.

**Trust boundary at KeyMaster.** KeyVault trusts whoever submits a `(KeyPath, CallConfig)`.
It is KeyMaster's job to decide who may submit what. Avatar authenticates clients via Nostr
identity (public key), but authorization policy lives in the KeyMaster layer.

**Semantic opacity at the vault.** KeyVault sees only bytes and call IDs. This keeps the
crypto engine small and auditable, and makes it portable to constrained environments (smart
cards, TEEs). All naming, routing, and policy live in KeyMaster.