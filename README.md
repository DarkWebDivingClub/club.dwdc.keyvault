# org.dwdc.keyvault

Minimal DWDC KeyVault library extracted from the existing IZ KeyVault codebase.

This repo intentionally starts with only the modules currently needed by the Android KeyMaster app:

- `org.dwdc.keyvault.core`
- `org.dwdc.keyvault.nostr`

Build locally:

```sh
mvn test
mvn install
```

Android dependency target:

```kotlin
implementation("org.dwdc:org.dwdc.keyvault.nostr:0.1.0")
```
