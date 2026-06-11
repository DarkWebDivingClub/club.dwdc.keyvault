package club.dwdc.keyvault.core;

/**
 * Vault execution interface. Performs operations on keys
 * identified by BIP-32 derivation paths.
 *
 * <p>Each operation is identified by a numeric function code.
 * The path selects the key; the function selects the operation.
 * Results carry a status code so callers can distinguish success from error.
 *
 * <p>Function code ranges:
 * <ul>
 *   <li>0–15: Generic functions (work the same regardless of protocol)</li>
 *   <li>16+: Protocol-specific functions (SSH, Nostr, … specializations)</li>
 * </ul>
 */
public interface KeyVault {

    // ── Generic functions (0–15) ─────────────────────────────────────────

    /** Export raw 32-byte BIP-32 leaf key material. */
    int FN_EXPORT_SEED = 0;

    /** Export the public key (algorithm-aware, derived from seed). */
    int FN_GET_PUBLIC_KEY = 1;

    /** Sign payload with the key at the given path. */
    int FN_SIGN = 2;

    /** Compute shared secret via key agreement (ECDH, X25519, …). */
    int FN_KEY_AGREEMENT = 3;

    // ── Protocol-specific functions (16+) ────────────────────────────────

    /**
     * Execute a function on the key identified by the derivation path.
     *
     * @param function operation to perform (FN_EXPORT_SEED, FN_GET_PUBLIC_KEY, FN_SIGN, FN_KEY_AGREEMENT, ...)
     * @param payload  data for the operation; null or empty for export functions
     * @param path     BIP-32 derivation path (each element: 31-bit index | optional hardened flag)
     * @return result with status code and output bytes
     */
    VaultResult execute(int function, byte[] payload, int... path);
}
