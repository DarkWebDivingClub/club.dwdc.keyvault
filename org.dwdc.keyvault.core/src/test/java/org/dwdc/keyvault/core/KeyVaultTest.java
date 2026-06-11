package org.dwdc.keyvault.core;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.bitcoinj.crypto.ECKey;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class KeyVaultTest {

    private static final String MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    private static final int H = 0x80000000;

    private static final int PURPOSE = 44 | H;
    private static final int SSH     = Protocol.SSH.coinType() | H;
    private static final int IDENTITY = Bip32KeyDerivator.mangle("alice@atlanta.com") | H;
    private static final int ALG_ED25519 = new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex() | H;
    private static final int ALG_SCHNORR = new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H;
    private static final int DEFAULT_CONFIG = new ConfigField(0, 0).toIndex() | H;

    private static final int NOSTR = Protocol.NOSTR.coinType() | H;
    private static final int NOSTR_IDENTITY = Bip32KeyDerivator.mangle("alice@nostr.com") | H;

    private final KeyVault vault = new Bip32KeyVault(MNEMONIC);

    // ── Export seed ──────────────────────────────────────────────────────

    @Test
    void exportSeedMatchesDerivator() {
        var derivator = new Bip32KeyDerivator(MNEMONIC);
        int[] path = {PURPOSE, SSH, IDENTITY, ALG_ED25519, DEFAULT_CONFIG};
        VaultResult result = vault.execute(KeyVault.FN_EXPORT_SEED, null, path);
        assertTrue(result.isOk());
        assertArrayEquals(derivator.derive(path), result.data());
    }

    // ── Get public key ───────────────────────────────────────────────────

    @Test
    void getPublicKeyReturns32Bytes() {
        VaultResult result = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null,
                PURPOSE, SSH, IDENTITY, ALG_ED25519, DEFAULT_CONFIG);
        assertTrue(result.isOk());
        assertEquals(32, result.data().length);
    }

    @Test
    void getPublicKeyIsDeterministic() {
        VaultResult first = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null,
                PURPOSE, SSH, IDENTITY, ALG_ED25519, DEFAULT_CONFIG);
        VaultResult second = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null,
                PURPOSE, SSH, IDENTITY, ALG_ED25519, DEFAULT_CONFIG);
        assertArrayEquals(first.data(), second.data());
    }

    @Test
    void differentPathsDifferentKeys() {
        int bobIdentity = Bip32KeyDerivator.mangle("bob@teahouse.com") | H;
        VaultResult alice = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null,
                PURPOSE, SSH, IDENTITY, ALG_ED25519, DEFAULT_CONFIG);
        VaultResult bob = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null,
                PURPOSE, SSH, bobIdentity, ALG_ED25519, DEFAULT_CONFIG);
        assertFalse(java.util.Arrays.equals(alice.data(), bob.data()));
    }

    // ── Schnorr / Nostr public key ───────────────────────────────────────

    @Test
    void getSchnorrPublicKeyReturns32Bytes() {
        VaultResult result = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null,
                PURPOSE, NOSTR, NOSTR_IDENTITY, ALG_SCHNORR, DEFAULT_CONFIG);
        assertTrue(result.isOk());
        assertEquals(32, result.data().length);
    }

    @Test
    void getSchnorrPublicKeyCrossCheck() {
        int[] path = {PURPOSE, NOSTR, NOSTR_IDENTITY, ALG_SCHNORR, DEFAULT_CONFIG};

        VaultResult seedResult = vault.execute(KeyVault.FN_EXPORT_SEED, null, path);
        assertTrue(seedResult.isOk());

        VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, path);
        assertTrue(pubResult.isOk());

        // Independent derivation using ECKey directly
        byte[] compressed = ECKey.fromPrivate(seedResult.data(), true).getPubKey();
        byte[] expected = Arrays.copyOfRange(compressed, 1, 33);
        assertArrayEquals(expected, pubResult.data());
    }

    // ── FN_SIGN + Schnorr ────────────────────────────────────────────────

    @Test
    void signSchnorrProduces64ByteSignature() {
        byte[] message = new byte[32];
        message[0] = 0x42;
        VaultResult result = vault.execute(KeyVault.FN_SIGN, message,
                PURPOSE, NOSTR, NOSTR_IDENTITY, ALG_SCHNORR, DEFAULT_CONFIG);
        assertTrue(result.isOk());
        assertEquals(64, result.data().length);
    }

    @Test
    void signSchnorrIsDeterministic() {
        byte[] message = new byte[32];
        message[0] = 0x01;
        VaultResult first = vault.execute(KeyVault.FN_SIGN, message,
                PURPOSE, NOSTR, NOSTR_IDENTITY, ALG_SCHNORR, DEFAULT_CONFIG);
        VaultResult second = vault.execute(KeyVault.FN_SIGN, message,
                PURPOSE, NOSTR, NOSTR_IDENTITY, ALG_SCHNORR, DEFAULT_CONFIG);
        assertArrayEquals(first.data(), second.data());
    }

    @Test
    void signSchnorrVerifiesWithECKey() {
        int[] path = {PURPOSE, NOSTR, NOSTR_IDENTITY, ALG_SCHNORR, DEFAULT_CONFIG};

        // Get the seed to build an ECKey for verification
        VaultResult seedResult = vault.execute(KeyVault.FN_EXPORT_SEED, null, path);
        assertTrue(seedResult.isOk());
        ECKey ecKey = ECKey.fromPrivate(seedResult.data(), true);

        // Sign a message via the vault
        byte[] message = sha256("test message".getBytes());
        VaultResult sigResult = vault.execute(KeyVault.FN_SIGN, message, path);
        assertTrue(sigResult.isOk());

        // Verify: reconstruct R and check the BIP-340 equation
        byte[] sig = sigResult.data();
        byte[] rx = Arrays.copyOf(sig, 32);
        byte[] sBytes = Arrays.copyOfRange(sig, 32, 64);

        var params = CustomNamedCurves.getByName("secp256k1");
        BigInteger n = params.getN();
        ECPoint G = params.getG();

        byte[] pubXOnly = Arrays.copyOfRange(ecKey.getPubKey(), 1, 33);

        // e = tagged_hash("BIP0340/challenge", rx || px || m) mod n
        byte[] eHash = Bip32KeyVault.taggedHash("BIP0340/challenge",
                concat(rx, pubXOnly, message));
        BigInteger e = new BigInteger(1, eHash).mod(n);
        BigInteger s = new BigInteger(1, sBytes);

        // R' = s*G - e*P  (should have x == rx and even y)
        BigInteger pubX = new BigInteger(1, pubXOnly);
        ECPoint P = liftX(params.getCurve(), pubX);
        ECPoint Rprime = G.multiply(s).add(P.multiply(e).negate()).normalize();

        assertArrayEquals(rx, Bip32KeyVault.bigIntTo32Bytes(Rprime.getXCoord().toBigInteger()));
        assertFalse(Rprime.getYCoord().toBigInteger().testBit(0), "R.y should be even");
    }

    // ── FN_SIGN + Ed25519 ────────────────────────────────────────────────

    @Test
    void signEd25519Produces64ByteSignature() {
        byte[] message = "hello world".getBytes();
        VaultResult result = vault.execute(KeyVault.FN_SIGN, message,
                PURPOSE, SSH, IDENTITY, ALG_ED25519, DEFAULT_CONFIG);
        assertTrue(result.isOk());
        assertEquals(64, result.data().length);
    }

    @Test
    void signEd25519VerifiesWithPublicKey() throws Exception {
        int[] path = {PURPOSE, SSH, IDENTITY, ALG_ED25519, DEFAULT_CONFIG};

        // Get public key
        VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, path);
        assertTrue(pubResult.isOk());

        // Sign
        byte[] message = "Ed25519 vault test".getBytes();
        VaultResult sigResult = vault.execute(KeyVault.FN_SIGN, message, path);
        assertTrue(sigResult.isOk());

        // Verify using EdDSAEngine
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("Ed25519");
        EdDSAPublicKeySpec pubSpec = new EdDSAPublicKeySpec(pubResult.data(), spec);
        EdDSAPublicKey pubKey = new EdDSAPublicKey(pubSpec);
        Signature verifier = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        verifier.initVerify(pubKey);
        verifier.update(message);
        assertTrue(verifier.verify(sigResult.data()));
    }

    // ── FN_SIGN error cases ──────────────────────────────────────────────

    @Test
    void signNullPayloadReturnsError() {
        VaultResult result = vault.execute(KeyVault.FN_SIGN, null,
                PURPOSE, NOSTR, NOSTR_IDENTITY, ALG_SCHNORR, DEFAULT_CONFIG);
        assertEquals(VaultResult.ERR_INVALID_PAYLOAD, result.status());
    }

    @Test
    void signEmptyPayloadReturnsError() {
        VaultResult result = vault.execute(KeyVault.FN_SIGN, new byte[0],
                PURPOSE, NOSTR, NOSTR_IDENTITY, ALG_SCHNORR, DEFAULT_CONFIG);
        assertEquals(VaultResult.ERR_INVALID_PAYLOAD, result.status());
    }

    @Test
    void signSchnorrWrongLengthReturnsError() {
        VaultResult result = vault.execute(KeyVault.FN_SIGN, new byte[16],
                PURPOSE, NOSTR, NOSTR_IDENTITY, ALG_SCHNORR, DEFAULT_CONFIG);
        assertEquals(VaultResult.ERR_INVALID_PAYLOAD, result.status());
    }

    @Test
    void signUnsupportedAlgorithmReturnsError() {
        int algRsa = new AlgField(AlgField.ALG_RSA, 0, 0).toIndex() | H;
        VaultResult result = vault.execute(KeyVault.FN_SIGN, new byte[32],
                PURPOSE, SSH, IDENTITY, algRsa, DEFAULT_CONFIG);
        assertEquals(VaultResult.ERR_UNSUPPORTED_ALGORITHM, result.status());
    }

    // ── FN_KEY_AGREEMENT + Schnorr (secp256k1) ───────────────────────────────────

    @Test
    void ecdhSchnorrReturns32Bytes() {
        int[] pathA = {PURPOSE, NOSTR, NOSTR_IDENTITY, ALG_SCHNORR, DEFAULT_CONFIG};
        int bobId = Bip32KeyDerivator.mangle("bob@nostr.com") | H;
        int[] pathB = {PURPOSE, NOSTR, bobId, ALG_SCHNORR, DEFAULT_CONFIG};

        VaultResult pubB = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, pathB);
        assertTrue(pubB.isOk());

        VaultResult shared = vault.execute(KeyVault.FN_KEY_AGREEMENT, pubB.data(), pathA);
        assertTrue(shared.isOk());
        assertEquals(32, shared.data().length);
    }

    @Test
    void ecdhSchnorrSymmetry() {
        // ECDH(a, B) == ECDH(b, A)
        int[] pathA = {PURPOSE, NOSTR, NOSTR_IDENTITY, ALG_SCHNORR, DEFAULT_CONFIG};
        int bobId = Bip32KeyDerivator.mangle("bob@nostr.com") | H;
        int[] pathB = {PURPOSE, NOSTR, bobId, ALG_SCHNORR, DEFAULT_CONFIG};

        VaultResult pubA = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, pathA);
        VaultResult pubB = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, pathB);
        assertTrue(pubA.isOk());
        assertTrue(pubB.isOk());

        VaultResult sharedAB = vault.execute(KeyVault.FN_KEY_AGREEMENT, pubB.data(), pathA);
        VaultResult sharedBA = vault.execute(KeyVault.FN_KEY_AGREEMENT, pubA.data(), pathB);
        assertTrue(sharedAB.isOk());
        assertTrue(sharedBA.isOk());

        assertArrayEquals(sharedAB.data(), sharedBA.data());
    }

    // ── FN_KEY_AGREEMENT + Ed25519 (X25519) ──────────────────────────────────────

    @Test
    void ecdhX25519Returns32Bytes() {
        int[] pathA = {PURPOSE, SSH, IDENTITY, ALG_ED25519, DEFAULT_CONFIG};
        int bobId = Bip32KeyDerivator.mangle("bob@ssh.com") | H;
        int[] pathB = {PURPOSE, SSH, bobId, ALG_ED25519, DEFAULT_CONFIG};

        // Derive X25519 public key for B from its seed
        VaultResult seedB = vault.execute(KeyVault.FN_EXPORT_SEED, null, pathB);
        assertTrue(seedB.isOk());
        byte[] x25519PubB = deriveX25519PublicKey(seedB.data());

        VaultResult shared = vault.execute(KeyVault.FN_KEY_AGREEMENT, x25519PubB, pathA);
        assertTrue(shared.isOk());
        assertEquals(32, shared.data().length);
    }

    @Test
    void ecdhX25519Symmetry() throws Exception {
        int[] pathA = {PURPOSE, SSH, IDENTITY, ALG_ED25519, DEFAULT_CONFIG};
        int bobId = Bip32KeyDerivator.mangle("bob@ssh.com") | H;
        int[] pathB = {PURPOSE, SSH, bobId, ALG_ED25519, DEFAULT_CONFIG};

        // Derive X25519 public keys from seeds
        VaultResult seedA = vault.execute(KeyVault.FN_EXPORT_SEED, null, pathA);
        VaultResult seedB = vault.execute(KeyVault.FN_EXPORT_SEED, null, pathB);
        assertTrue(seedA.isOk());
        assertTrue(seedB.isOk());

        byte[] x25519PubA = deriveX25519PublicKey(seedA.data());
        byte[] x25519PubB = deriveX25519PublicKey(seedB.data());

        VaultResult sharedAB = vault.execute(KeyVault.FN_KEY_AGREEMENT, x25519PubB, pathA);
        VaultResult sharedBA = vault.execute(KeyVault.FN_KEY_AGREEMENT, x25519PubA, pathB);
        assertTrue(sharedAB.isOk());
        assertTrue(sharedBA.isOk());

        assertArrayEquals(sharedAB.data(), sharedBA.data());
    }

    // ── FN_KEY_AGREEMENT error cases ──────────────────────────────────────────────

    @Test
    void ecdhNullPayloadReturnsError() {
        VaultResult result = vault.execute(KeyVault.FN_KEY_AGREEMENT, null,
                PURPOSE, NOSTR, NOSTR_IDENTITY, ALG_SCHNORR, DEFAULT_CONFIG);
        assertEquals(VaultResult.ERR_INVALID_PAYLOAD, result.status());
    }

    @Test
    void ecdhEmptyPayloadReturnsError() {
        VaultResult result = vault.execute(KeyVault.FN_KEY_AGREEMENT, new byte[0],
                PURPOSE, NOSTR, NOSTR_IDENTITY, ALG_SCHNORR, DEFAULT_CONFIG);
        assertEquals(VaultResult.ERR_INVALID_PAYLOAD, result.status());
    }

    @Test
    void ecdhWrongLengthReturnsError() {
        VaultResult result = vault.execute(KeyVault.FN_KEY_AGREEMENT, new byte[16],
                PURPOSE, NOSTR, NOSTR_IDENTITY, ALG_SCHNORR, DEFAULT_CONFIG);
        assertEquals(VaultResult.ERR_INVALID_PAYLOAD, result.status());
    }

    // ── Error cases ──────────────────────────────────────────────────────

    @Test
    void unsupportedFunctionReturnsError() {
        VaultResult result = vault.execute(999, null,
                PURPOSE, SSH, IDENTITY, ALG_ED25519, DEFAULT_CONFIG);
        assertEquals(VaultResult.ERR_UNSUPPORTED_FUNCTION, result.status());
    }

    @Test
    void unsupportedAlgorithmReturnsError() {
        int algRsa = new AlgField(AlgField.ALG_RSA, 0, 0).toIndex() | H;
        VaultResult result = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null,
                PURPOSE, SSH, IDENTITY, algRsa, DEFAULT_CONFIG);
        assertEquals(VaultResult.ERR_UNSUPPORTED_ALGORITHM, result.status());
    }

    @Test
    void invalidPathReturnsError() {
        VaultResult result = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null,
                PURPOSE, SSH, IDENTITY);
        assertEquals(VaultResult.ERR_INVALID_PATH, result.status());
    }

    // ── Test helpers ─────────────────────────────────────────────────────

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Derive X25519 public key from Ed25519 seed (same derivation as vault). */
    private static byte[] deriveX25519PublicKey(byte[] ed25519Seed) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-512").digest(ed25519Seed);
            byte[] x25519Seed = Arrays.copyOf(hash, 32);
            x25519Seed[0]  &= (byte) 0xF8;
            x25519Seed[31] &= (byte) 0x7F;
            x25519Seed[31] |= (byte) 0x40;

            var privKey = new org.bouncycastle.crypto.params.X25519PrivateKeyParameters(x25519Seed, 0);
            return privKey.generatePublicKey().getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Lift x to a point on secp256k1 (even y). */
    private static ECPoint liftX(org.bouncycastle.math.ec.ECCurve curve, BigInteger x) {
        org.bouncycastle.math.ec.ECFieldElement xElem = curve.fromBigInteger(x);
        org.bouncycastle.math.ec.ECFieldElement ySquared = xElem.square().multiply(xElem)
                .add(curve.getB());
        org.bouncycastle.math.ec.ECFieldElement y = ySquared.sqrt();
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
}
