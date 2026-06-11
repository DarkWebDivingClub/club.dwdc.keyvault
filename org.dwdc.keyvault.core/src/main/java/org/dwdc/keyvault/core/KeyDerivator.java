package org.dwdc.keyvault.core;

/**
 * Derives raw 32-byte key material from a BIP-32 derivation path.
 *
 * Each element in the path is a full 32-bit child number
 * (bit 31 = hardened flag, bits 30-0 = index).
 */
public interface KeyDerivator {

    byte[] derive(int... path);
}
