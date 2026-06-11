# club.dwdc.keyvault

Minimal DWDC KeyVault library extracted from the existing IZ KeyVault codebase.

This repo intentionally starts with only the modules currently needed by the Android KeyMaster app:

- `club.dwdc.keyvault.core`
- `club.dwdc.keyvault.nostr`

Build locally:

```sh
mvn test
mvn install
```

Android dependency target:

```kotlin
implementation("club.dwdc:club.dwdc.keyvault.nostr:0.1.0")
```
