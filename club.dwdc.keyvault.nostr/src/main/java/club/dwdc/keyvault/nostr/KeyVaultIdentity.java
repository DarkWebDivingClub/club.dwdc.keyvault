package club.dwdc.keyvault.nostr;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.core.VaultResult;
import nostr.base.ISignable;
import nostr.base.PublicKey;
import nostr.base.Signature;
import nostr.id.IIdentity;
import nostr.id.SigningException;
import nostr.util.NostrUtil;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.function.Consumer;

/**
 * {@link IIdentity} backed by a {@link KeyVault}.
 * Private keys never leave the vault — all cryptographic operations
 * (public-key derivation, signing, ECDH) are delegated to
 * {@link KeyVault#execute}.
 */
public class KeyVaultIdentity implements IIdentity {

    private static final int H = 0x80000000;
    private static final int PURPOSE = 44 | H;
    private static final int NOSTR_COIN = Protocol.NOSTR.coinType() | H;
    private static final int ALG_SCHNORR =
            new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H;
    private static final int DEFAULT_CONFIG =
            new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H;

    private final KeyVault vault;
    private final int[] path;
    private PublicKey cachedPublicKey;

    /**
     * @param vault    the vault that holds the key material
     * @param identity human-readable identity string (e.g. "alice@nostr.com"),
     *                 mangled into path level 3 via {@link Bip32KeyDerivator#mangle}
     */
    public KeyVaultIdentity(KeyVault vault, String identity) {
        this.vault = vault;
        int identityIndex = Bip32KeyDerivator.mangle(identity) | H;
        this.path = new int[]{PURPOSE, NOSTR_COIN, identityIndex, ALG_SCHNORR, DEFAULT_CONFIG};
    }

    @Override
    public PublicKey getPublicKey() {
        if (cachedPublicKey == null) {
            VaultResult result = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, path);
            if (!result.isOk()) {
                throw new IllegalStateException(
                        "Vault FN_GET_PUBLIC_KEY failed: status=" + result.status());
            }
            cachedPublicKey = new PublicKey(result.data());
        }
        return cachedPublicKey;
    }

    @Override
    public Signature sign(ISignable signable) {
        try {
            byte[] hash = NostrUtil.sha256(
                    signable.getByteArraySupplier().get().array());

            VaultResult result = vault.execute(KeyVault.FN_SIGN, hash, path);
            if (!result.isOk()) {
                throw new SigningException(
                        "Vault FN_SIGN failed: status=" + result.status());
            }

            Signature signature = new Signature();
            signature.setRawData(result.data());
            signature.setPubKey(getPublicKey());

            Consumer<Signature> consumer = signable.getSignatureConsumer();
            if (consumer != null) {
                consumer.accept(signature);
            }
            return signature;
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm not available", ex);
        } catch (SigningException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new SigningException("Signing failed", ex);
        }
    }

    /**
     * Signs a pre-hashed 32-byte message (e.g. a Nostr event ID that is
     * already SHA-256).  Unlike {@link #sign(ISignable)}, this skips the
     * internal SHA-256 step so callers that already hold a hash can avoid
     * double-hashing.
     *
     * @param hash 32-byte hash to sign
     * @return 64-byte BIP-340 Schnorr signature
     */
    public byte[] signPrehashed(byte[] hash) {
        VaultResult result = vault.execute(KeyVault.FN_SIGN, hash, path);
        if (!result.isOk()) {
            throw new IllegalStateException("Vault FN_SIGN failed: status=" + result.status());
        }
        return result.data();
    }

    /**
     * Computes the NIP-44 conversation key with the given recipient.
     * <ol>
     *   <li>ECDH via vault: shared_x = x-coordinate of (privKey * recipientPubKey)</li>
     *   <li>HKDF-Extract: conversation_key = HMAC-SHA256(salt="nip44-v2", ikm=shared_x)</li>
     * </ol>
     *
     * @return 32-byte NIP-44 conversation key
     */
    @Override
    public byte[] computeSharedSecret(PublicKey recipientPubKey) {
        VaultResult result = vault.execute(
                KeyVault.FN_KEY_AGREEMENT, recipientPubKey.getRawData(), path);
        if (!result.isOk()) {
            throw new IllegalStateException(
                    "Vault FN_KEY_AGREEMENT failed: status=" + result.status());
        }

        // NIP-44: conversation_key = HKDF-Extract(salt="nip44-v2", ikm=shared_x)
        try {
            byte[] salt = "nip44-v2".getBytes(StandardCharsets.UTF_8);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            return mac.doFinal(result.data());
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("HKDF-Extract failed", e);
        }
    }
}
