package org.dwdc.keyvault.core;

/**
 * Level 4: alg(15 bits) | variant(8 bits) | role(8 bits) = 31 bits
 *
 * Bit 31        Bit 0
 * H | alg(30-16) | variant(15-8) | role(7-0)
 */
public record AlgField(int alg, int variant, int role) {

    public int toIndex() {
        return ((alg & 0x7FFF) << 16) | ((variant & 0xFF) << 8) | (role & 0xFF);
    }

    // Convenience constants
    public static final int ALG_SCHNORR = 0;
    public static final int ALG_ED25519 = 1;
    public static final int ALG_RSA     = 2;
    public static final int ALG_ECDSA   = 3;
}
