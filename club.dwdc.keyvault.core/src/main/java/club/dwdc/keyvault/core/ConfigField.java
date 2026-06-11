package club.dwdc.keyvault.core;

/**
 * Level 5: csprng(7 bits) | index(24 bits) = 31 bits
 *
 * Bit 31        Bit 0
 * H | csprng(30-24) | index(23-0)
 */
public record ConfigField(int csprng, int index) {

    public int toIndex() {
        return ((csprng & 0x7F) << 24) | (index & 0xFFFFFF);
    }

    public static final int CSPRNG_NONE      = 0;
    public static final int CSPRNG_HMAC_DRBG = 1;
    public static final int CSPRNG_CTR_DRBG  = 2;
    public static final int CSPRNG_CHACHA20  = 3;
}
