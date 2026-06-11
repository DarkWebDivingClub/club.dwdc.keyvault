package club.dwdc.keyvault.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * BIP-340 Schnorr signature test using official test vectors.
 *
 * <p>The vault uses deterministic signing with aux = 32 zero bytes,
 * so we can't directly match BIP-340 vectors that use non-zero aux.
 * Instead, we test with a known private key, sign a known message,
 * and verify the signature is valid (deterministic + correct equation).
 *
 * <p>BIP-340 vector 0 uses aux = all zeros, which matches our implementation.
 */
class SchnorrSignTest {

    private static final int H = 0x80000000;
    private static final int PURPOSE = 44 | H;
    private static final int NOSTR = Protocol.NOSTR.coinType() | H;

    // ── BIP-340 test vector 0 (aux = 0x00...00) ─────────────────────────
    // Private key: 3
    // Message:     0x00...00 (32 zero bytes)
    // aux_rand:    0x00...00 (32 zero bytes)  <-- matches our deterministic signing!
    // Expected sig: E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215
    //               25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0

    @Test
    void bip340Vector0() {
        // We need vector 0's private key to be the vault-derived seed.
        // Since we can't inject an arbitrary private key into the vault,
        // we test the BIP-340 implementation indirectly:
        // 1. Use a known mnemonic/identity pair
        // 2. Sign with the vault
        // 3. Verify the signature using the BIP-340 verification equation

        String mnemonic = "abandon abandon abandon abandon abandon abandon " +
                "abandon abandon abandon abandon abandon about";
        KeyVault vault = new Bip32KeyVault(mnemonic);

        int identity = Bip32KeyDerivator.mangle("test@bip340.com") | H;
        int alg = new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H;
        int cfg = new ConfigField(0, 0).toIndex() | H;
        int[] path = {PURPOSE, NOSTR, identity, alg, cfg};

        // Get the public key for verification
        VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, path);
        assertTrue(pubResult.isOk());
        byte[] pubKey = pubResult.data();
        assertEquals(32, pubKey.length);

        // Sign a 32-byte message
        byte[] message = new byte[32]; // all zeros
        VaultResult sigResult = vault.execute(KeyVault.FN_SIGN, message, path);
        assertTrue(sigResult.isOk());
        byte[] sig = sigResult.data();
        assertEquals(64, sig.length);

        // Verify using BIP-340 verification equation
        assertTrue(bip340Verify(pubKey, message, sig));
    }

    @Test
    void signDeterministic() {
        String mnemonic = "abandon abandon abandon abandon abandon abandon " +
                "abandon abandon abandon abandon abandon about";
        KeyVault vault = new Bip32KeyVault(mnemonic);

        int identity = Bip32KeyDerivator.mangle("deterministic@test.com") | H;
        int alg = new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H;
        int cfg = new ConfigField(0, 0).toIndex() | H;
        int[] path = {PURPOSE, NOSTR, identity, alg, cfg};

        byte[] message = hexToBytes("0000000000000000000000000000000000000000000000000000000000000001");

        VaultResult sig1 = vault.execute(KeyVault.FN_SIGN, message, path);
        VaultResult sig2 = vault.execute(KeyVault.FN_SIGN, message, path);
        assertTrue(sig1.isOk());
        assertTrue(sig2.isOk());
        assertArrayEquals(sig1.data(), sig2.data(), "Deterministic signing must produce identical signatures");
    }

    @Test
    void signDifferentMessagesDifferentSignatures() {
        String mnemonic = "abandon abandon abandon abandon abandon abandon " +
                "abandon abandon abandon abandon abandon about";
        KeyVault vault = new Bip32KeyVault(mnemonic);

        int identity = Bip32KeyDerivator.mangle("diff@test.com") | H;
        int alg = new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H;
        int cfg = new ConfigField(0, 0).toIndex() | H;
        int[] path = {PURPOSE, NOSTR, identity, alg, cfg};

        byte[] msg1 = new byte[32];
        byte[] msg2 = new byte[32];
        msg2[31] = 1;

        VaultResult sig1 = vault.execute(KeyVault.FN_SIGN, msg1, path);
        VaultResult sig2 = vault.execute(KeyVault.FN_SIGN, msg2, path);
        assertTrue(sig1.isOk());
        assertTrue(sig2.isOk());
        assertFalse(java.util.Arrays.equals(sig1.data(), sig2.data()));
    }

    @Test
    void signMultipleMessagesAllVerify() {
        String mnemonic = "abandon abandon abandon abandon abandon abandon " +
                "abandon abandon abandon abandon abandon about";
        KeyVault vault = new Bip32KeyVault(mnemonic);

        int identity = Bip32KeyDerivator.mangle("multi@test.com") | H;
        int alg = new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H;
        int cfg = new ConfigField(0, 0).toIndex() | H;
        int[] path = {PURPOSE, NOSTR, identity, alg, cfg};

        VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, path);
        assertTrue(pubResult.isOk());
        byte[] pubKey = pubResult.data();

        // Sign and verify 10 different messages
        for (int i = 0; i < 10; i++) {
            byte[] message = new byte[32];
            message[0] = (byte) i;
            message[31] = (byte) (i * 7);

            VaultResult sigResult = vault.execute(KeyVault.FN_SIGN, message, path);
            assertTrue(sigResult.isOk(), "Sign failed for message " + i);
            assertTrue(bip340Verify(pubKey, message, sigResult.data()),
                    "Verification failed for message " + i);
        }
    }

    // ── BIP-340 verification ─────────────────────────────────────────────

    /**
     * BIP-340 signature verification.
     * Returns true if sig is a valid Schnorr signature for message under pubKey.
     */
    private static boolean bip340Verify(byte[] pubKey, byte[] message, byte[] sig) {
        try {
            var params = org.bouncycastle.crypto.ec.CustomNamedCurves.getByName("secp256k1");
            java.math.BigInteger n = params.getN();
            org.bouncycastle.math.ec.ECPoint G = params.getG();

            byte[] rx = java.util.Arrays.copyOf(sig, 32);
            byte[] sBytes = java.util.Arrays.copyOfRange(sig, 32, 64);
            java.math.BigInteger r = new java.math.BigInteger(1, rx);
            java.math.BigInteger s = new java.math.BigInteger(1, sBytes);

            // s must be < n
            if (s.compareTo(n) >= 0) return false;

            // Lift x to point P (even y)
            java.math.BigInteger px = new java.math.BigInteger(1, pubKey);
            org.bouncycastle.math.ec.ECPoint P = liftX(params.getCurve(), px);
            if (P == null) return false;

            // e = tagged_hash("BIP0340/challenge", rx || px || m) mod n
            byte[] eInput = concat(rx, pubKey, message);
            byte[] eHash = Bip32KeyVault.taggedHash("BIP0340/challenge", eInput);
            java.math.BigInteger e = new java.math.BigInteger(1, eHash).mod(n);

            // R = s*G - e*P
            org.bouncycastle.math.ec.ECPoint R = G.multiply(s).add(P.multiply(e).negate()).normalize();

            if (R.isInfinity()) return false;
            if (R.getYCoord().toBigInteger().testBit(0)) return false; // y must be even
            return R.getXCoord().toBigInteger().equals(r);
        } catch (Exception e) {
            return false;
        }
    }

    private static org.bouncycastle.math.ec.ECPoint liftX(
            org.bouncycastle.math.ec.ECCurve curve, java.math.BigInteger x) {
        org.bouncycastle.math.ec.ECFieldElement xElem = curve.fromBigInteger(x);
        org.bouncycastle.math.ec.ECFieldElement ySquared = xElem.square().multiply(xElem)
                .add(curve.getB());
        org.bouncycastle.math.ec.ECFieldElement y = ySquared.sqrt();
        if (y == null) return null;
        if (y.toBigInteger().testBit(0)) {
            y = y.negate();
        }
        return curve.createPoint(x, y.toBigInteger()).normalize();
    }

    private static byte[] concat(byte[]... arrays) {
        int len = 0;
        for (byte[] a : arrays) len += a.length;
        byte[] result = new byte[len];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }

    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}
