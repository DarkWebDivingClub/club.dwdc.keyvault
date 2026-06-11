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

## License

This project is licensed under the GNU General Public License v3.0 only
(`GPL-3.0-only`). See [LICENSE](LICENSE).
