package club.dwdc.keyvault.core;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bitcoinj.crypto.ECKey;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Arrays;

public class Bip32KeyVault implements KeyVault {

    private static final EdDSAParameterSpec ED25519_SPEC =
            EdDSANamedCurveTable.getByName("Ed25519");

    private static final ECDomainParameters SECP256K1;
    static {
        var params = CustomNamedCurves.getByName("secp256k1");
        SECP256K1 = new ECDomainParameters(
                params.getCurve(), params.getG(), params.getN(), params.getH());
    }

    private final Bip32KeyDerivator derivator;

    /** Create from BIP-39 mnemonic (no passphrase). */
    public Bip32KeyVault(String mnemonic) {
        this(mnemonic, "");
    }

    /** Create from BIP-39 mnemonic with optional passphrase. */
    public Bip32KeyVault(String mnemonic, String passphrase) {
        this.derivator = new Bip32KeyDerivator(mnemonic, passphrase);
    }

    @Override
    public VaultResult execute(int function, byte[] payload, int... path) {
        if (path.length < 5) {
            return VaultResult.error(VaultResult.ERR_INVALID_PATH);
        }

        return switch (function) {
            case FN_EXPORT_SEED -> VaultResult.ok(derivator.derive(path));
            case FN_GET_PUBLIC_KEY -> getPublicKey(path);
            case FN_SIGN -> sign(path, payload);
            case FN_KEY_AGREEMENT -> ecdh(path, payload);
            default -> VaultResult.error(VaultResult.ERR_UNSUPPORTED_FUNCTION);
        };
    }

    /** Extract the algorithm ID from path level 4 (index 3). */
    private static int extractAlg(int[] path) {
        int algIndex = path[3] & 0x7FFFFFFF;
        return (algIndex >> 16) & 0x7FFF;
    }

    // ── FN_GET_PUBLIC_KEY ────────────────────────────────────────────────

    private VaultResult getPublicKey(int[] path) {
        int alg = extractAlg(path);
        byte[] seed = derivator.derive(path);

        return switch (alg) {
            case AlgField.ALG_ED25519 -> {
                EdDSAPrivateKeySpec privSpec = new EdDSAPrivateKeySpec(seed, ED25519_SPEC);
                yield VaultResult.ok(privSpec.getA().toByteArray());
            }
            case AlgField.ALG_SCHNORR -> {
                byte[] compressed = ECKey.fromPrivate(seed, true).getPubKey();
                // x-only Schnorr public key: strip the 0x02/0x03 prefix byte
                yield VaultResult.ok(Arrays.copyOfRange(compressed, 1, 33));
            }
            default -> VaultResult.error(VaultResult.ERR_UNSUPPORTED_ALGORITHM);
        };
    }

    // ── FN_SIGN ──────────────────────────────────────────────────────────

    private VaultResult sign(int[] path, byte[] payload) {
        if (payload == null || payload.length == 0) {
            return VaultResult.error(VaultResult.ERR_INVALID_PAYLOAD);
        }

        int alg = extractAlg(path);
        byte[] seed = derivator.derive(path);

        return switch (alg) {
            case AlgField.ALG_SCHNORR -> schnorrSign(seed, payload);
            case AlgField.ALG_ED25519 -> ed25519Sign(seed, payload);
            default -> VaultResult.error(VaultResult.ERR_UNSUPPORTED_ALGORITHM);
        };
    }

    /**
     * BIP-340 Schnorr signature over secp256k1.
     * Deterministic signing (aux randomness = 32 zero bytes).
     *
     * @param seed    32-byte private key
     * @param message 32-byte message hash
     * @return 64-byte signature (R.x || s)
     */
    private VaultResult schnorrSign(byte[] seed, byte[] message) {
        if (message.length != 32) {
            return VaultResult.error(VaultResult.ERR_INVALID_PAYLOAD);
        }

        try {
            BigInteger n = SECP256K1.getN();
            ECPoint G = SECP256K1.getG();

            BigInteger d = new BigInteger(1, seed);
            ECPoint P = G.multiply(d).normalize();
            byte[] px = bigIntTo32Bytes(P.getXCoord().toBigInteger());

            // If P.y is odd, negate d
            BigInteger dAdj = P.getYCoord().toBigInteger().testBit(0)
                    ? n.subtract(d) : d;

            // Deterministic nonce: k = tagged_hash("BIP0340/nonce", t || px || m) mod n
            byte[] aux = new byte[32];
            byte[] t = xorBytes(bigIntTo32Bytes(dAdj), taggedHash("BIP0340/aux", aux));
            byte[] nonceInput = concat(t, px, message);
            byte[] kHash = taggedHash("BIP0340/nonce", nonceInput);
            BigInteger k = new BigInteger(1, kHash).mod(n);
            if (k.equals(BigInteger.ZERO)) {
                return VaultResult.error(VaultResult.ERR_CRYPTO_FAILURE);
            }

            ECPoint R = G.multiply(k).normalize();
            if (R.getYCoord().toBigInteger().testBit(0)) {
                k = n.subtract(k);
            }
            byte[] rx = bigIntTo32Bytes(R.getXCoord().toBigInteger());

            // Challenge: e = tagged_hash("BIP0340/challenge", rx || px || m) mod n
            byte[] eHash = taggedHash("BIP0340/challenge", concat(rx, px, message));
            BigInteger e = new BigInteger(1, eHash).mod(n);

            // s = (k + e * dAdj) mod n
            BigInteger s = k.add(e.multiply(dAdj)).mod(n);

            return VaultResult.ok(concat(rx, bigIntTo32Bytes(s)));
        } catch (Exception ex) {
            return VaultResult.error(VaultResult.ERR_CRYPTO_FAILURE);
        }
    }

    /**
     * Ed25519 signature using net.i2p.crypto.eddsa.
     *
     * @param seed    32-byte Ed25519 seed
     * @param message raw message bytes (Ed25519 hashes internally)
     * @return 64-byte Ed25519 signature
     */
    private VaultResult ed25519Sign(byte[] seed, byte[] message) {
        try {
            EdDSAPrivateKeySpec privSpec = new EdDSAPrivateKeySpec(seed, ED25519_SPEC);
            EdDSAPrivateKey privKey = new EdDSAPrivateKey(privSpec);
            Signature sig = new EdDSAEngine(MessageDigest.getInstance(ED25519_SPEC.getHashAlgorithm()));
            sig.initSign(privKey);
            sig.update(message);
            return VaultResult.ok(sig.sign());
        } catch (Exception ex) {
            return VaultResult.error(VaultResult.ERR_CRYPTO_FAILURE);
        }
    }

    // ── FN_KEY_AGREEMENT ──────────────────────────────────────────────────────────

    private VaultResult ecdh(int[] path, byte[] payload) {
        if (payload == null || payload.length == 0) {
            return VaultResult.error(VaultResult.ERR_INVALID_PAYLOAD);
        }

        int alg = extractAlg(path);
        byte[] seed = derivator.derive(path);

        return switch (alg) {
            case AlgField.ALG_SCHNORR -> secp256k1Ecdh(seed, payload);
            case AlgField.ALG_ED25519 -> x25519Ecdh(seed, payload);
            default -> VaultResult.error(VaultResult.ERR_UNSUPPORTED_ALGORITHM);
        };
    }

    /**
     * secp256k1 ECDH: shared secret = x-coordinate of (privKey * theirPubKey).
     *
     * @param seed    32-byte private key
     * @param payload 32-byte x-only pubkey (even Y assumed) or 33-byte compressed pubkey
     * @return 32-byte shared secret (x-coordinate)
     */
    private VaultResult secp256k1Ecdh(byte[] seed, byte[] payload) {
        if (payload.length != 32 && payload.length != 33) {
            return VaultResult.error(VaultResult.ERR_INVALID_PAYLOAD);
        }

        try {
            // If 32-byte x-only, prepend 0x02 (even Y)
            byte[] compressed;
            if (payload.length == 32) {
                compressed = new byte[33];
                compressed[0] = 0x02;
                System.arraycopy(payload, 0, compressed, 1, 32);
            } else {
                compressed = payload;
            }

            ECPoint theirPoint = SECP256K1.getCurve().decodePoint(compressed).normalize();
            BigInteger privKey = new BigInteger(1, seed);
            ECPoint shared = theirPoint.multiply(privKey).normalize();

            return VaultResult.ok(bigIntTo32Bytes(shared.getXCoord().toBigInteger()));
        } catch (Exception ex) {
            return VaultResult.error(VaultResult.ERR_CRYPTO_FAILURE);
        }
    }

    /**
     * X25519 key agreement: derive X25519 private key from Ed25519 seed (clamped),
     * then compute shared secret.
     *
     * @param seed    32-byte Ed25519 seed
     * @param payload 32-byte X25519 public key
     * @return 32-byte shared secret
     */
    private VaultResult x25519Ecdh(byte[] seed, byte[] payload) {
        if (payload.length != 32) {
            return VaultResult.error(VaultResult.ERR_INVALID_PAYLOAD);
        }

        try {
            // Derive X25519 private key from Ed25519 seed:
            // hash the seed with SHA-512, take first 32 bytes, then clamp
            byte[] hash = MessageDigest.getInstance("SHA-512").digest(seed);
            byte[] x25519Seed = Arrays.copyOf(hash, 32);
            x25519Seed[0]  &= (byte) 0xF8;  // clear bottom 3 bits
            x25519Seed[31] &= (byte) 0x7F;  // clear top bit
            x25519Seed[31] |= (byte) 0x40;  // set second-to-top bit

            X25519PrivateKeyParameters privKey = new X25519PrivateKeyParameters(x25519Seed, 0);
            X25519PublicKeyParameters theirPubKey = new X25519PublicKeyParameters(payload, 0);

            X25519Agreement agreement = new X25519Agreement();
            agreement.init(privKey);
            byte[] secret = new byte[agreement.getAgreementSize()];
            agreement.calculateAgreement(theirPubKey, secret, 0);

            return VaultResult.ok(secret);
        } catch (Exception ex) {
            return VaultResult.error(VaultResult.ERR_CRYPTO_FAILURE);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /** BIP-340 tagged hash: SHA-256(SHA-256(tag) || SHA-256(tag) || data) */
    static byte[] taggedHash(String tag, byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] tagHash = md.digest(tag.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.reset();
            md.update(tagHash);
            md.update(tagHash);
            md.update(data);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] bigIntTo32Bytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == 32) return bytes;
        if (bytes.length > 32) return Arrays.copyOfRange(bytes, bytes.length - 32, bytes.length);
        byte[] padded = new byte[32];
        System.arraycopy(bytes, 0, padded, 32 - bytes.length, bytes.length);
        return padded;
    }

    private static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
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
