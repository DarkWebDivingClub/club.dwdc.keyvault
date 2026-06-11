package club.dwdc.keyvault.core;

import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.wallet.DeterministicSeed;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Bip32KeyDerivator implements KeyDerivator {

    private final DeterministicKey master;

    /** Create from BIP-39 mnemonic (no passphrase). */
    public Bip32KeyDerivator(String mnemonic) {
        this(mnemonic, "");
    }

    /** Create from BIP-39 mnemonic with optional passphrase. */
    public Bip32KeyDerivator(String mnemonic, String passphrase) {
        DeterministicSeed ds = DeterministicSeed.ofMnemonic(mnemonic, passphrase);
        this.master = HDKeyDerivation.createMasterPrivateKey(ds.getSeedBytes());
    }

    /** Create from raw 64-byte seed. */
    public Bip32KeyDerivator(byte[] seed) {
        this.master = HDKeyDerivation.createMasterPrivateKey(seed);
    }

    @Override
    public byte[] derive(int... path) {
        DeterministicKey key = master;
        for (int child : path) {
            key = HDKeyDerivation.deriveChildKey(key, new ChildNumber(child));
        }
        return key.getPrivKeyBytes();
    }

    /** SHA-256(value) -> first 4 bytes -> 31-bit unsigned int. */
    public static int mangle(String value) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return ((hash[0] & 0xFF) << 24
                    | (hash[1] & 0xFF) << 16
                    | (hash[2] & 0xFF) << 8
                    | (hash[3] & 0xFF)) & 0x7FFFFFFF;
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-256 not available", e);
        }
    }
}
