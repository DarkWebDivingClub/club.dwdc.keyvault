package org.dwdc.keyvault.nostr;

import org.dwdc.keyvault.core.AlgField;
import org.dwdc.keyvault.core.Bip32KeyDerivator;
import org.dwdc.keyvault.core.Bip32KeyVault;
import org.dwdc.keyvault.core.ConfigField;
import org.dwdc.keyvault.core.KeyVault;
import org.dwdc.keyvault.core.Protocol;
import org.dwdc.keyvault.core.VaultResult;
import nostr.base.ISignable;
import nostr.base.PrivateKey;
import nostr.base.PublicKey;
import nostr.base.Signature;
import nostr.crypto.schnorr.Schnorr;
import nostr.encryption.MessageCipher44;
import nostr.event.impl.GenericEvent;
import nostr.id.Identity;
import nostr.util.NostrUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

class KeyVaultIdentityTest {

    @BeforeAll
    static void registerBouncyCastle() {
        // BC must be first so EncryptedPayloads' Cipher.getInstance("ChaCha20")
        // picks BC (which accepts IvParameterSpec) over JDK's SunJCE.
        if (Security.getProvider("BC") == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    private static final String MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    private static final int H = 0x80000000;
    private static final int PURPOSE = 44 | H;
    private static final int NOSTR_COIN = Protocol.NOSTR.coinType() | H;
    private static final int ALG_SCHNORR =
            new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H;
    private static final int DEFAULT_CONFIG =
            new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H;

    private final KeyVault vault = new Bip32KeyVault(MNEMONIC);
    private final KeyVaultIdentity identityAlice =
            new KeyVaultIdentity(vault, "alice@nostr.com");
    private final KeyVaultIdentity identityBob =
            new KeyVaultIdentity(vault, "bob@nostr.com");

    // ── getPublicKey ─────────────────────────────────────────────────────

    @Test
    void getPublicKeyMatchesDirectVaultCall() {
        int identityIndex = Bip32KeyDerivator.mangle("alice@nostr.com") | H;
        int[] path = {PURPOSE, NOSTR_COIN, identityIndex, ALG_SCHNORR, DEFAULT_CONFIG};

        VaultResult expected = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, path);
        assertTrue(expected.isOk());

        PublicKey pubKey = identityAlice.getPublicKey();
        assertArrayEquals(expected.data(), pubKey.getRawData());
    }

    @Test
    void getPublicKeyIsCached() {
        PublicKey first = identityAlice.getPublicKey();
        PublicKey second = identityAlice.getPublicKey();
        assertSame(first, second);
    }

    // ── sign ─────────────────────────────────────────────────────────────

    @Test
    void signProducesValidSchnorrSignature() throws Exception {
        byte[] message = "test message for signing".getBytes();
        ISignable signable = testSignable(message);

        Signature sig = identityAlice.sign(signable);

        assertNotNull(sig);
        assertNotNull(sig.getRawData());
        assertEquals(64, sig.getRawData().length);
        assertEquals(identityAlice.getPublicKey(), sig.getPubKey());

        // Verify using nostr-java's Schnorr.verify
        byte[] hash = NostrUtil.sha256(message);
        assertTrue(Schnorr.verify(hash,
                identityAlice.getPublicKey().getRawData(), sig.getRawData()));
    }

    @Test
    void signSetsSignatureOnSignable() {
        byte[] message = "signable consumer test".getBytes();
        ISignable signable = testSignable(message);

        Signature returned = identityAlice.sign(signable);

        assertNotNull(signable.getSignature());
        assertSame(returned, signable.getSignature());
    }

    // ── computeSharedSecret ──────────────────────────────────────────────

    @Test
    void computeSharedSecretSymmetry() {
        // ECDH(alice, bobPub) == ECDH(bob, alicePub)
        byte[] secretAB = identityAlice.computeSharedSecret(identityBob.getPublicKey());
        byte[] secretBA = identityBob.computeSharedSecret(identityAlice.getPublicKey());

        assertNotNull(secretAB);
        assertEquals(32, secretAB.length);
        assertArrayEquals(secretAB, secretBA);
    }

    @Test
    void computeSharedSecretMatchesIdentity() {
        // Extract private key seed from vault and create a nostr-java Identity
        int aliceIndex = Bip32KeyDerivator.mangle("alice@nostr.com") | H;
        int[] alicePath = {PURPOSE, NOSTR_COIN, aliceIndex, ALG_SCHNORR, DEFAULT_CONFIG};
        VaultResult seedResult = vault.execute(KeyVault.FN_EXPORT_SEED, null, alicePath);
        assertTrue(seedResult.isOk());

        Identity plainIdentity = Identity.create(new PrivateKey(seedResult.data()));

        // Both should produce the same conversation key for Bob's public key
        byte[] vaultSecret = identityAlice.computeSharedSecret(identityBob.getPublicKey());
        byte[] plainSecret = plainIdentity.computeSharedSecret(identityBob.getPublicKey());

        assertArrayEquals(plainSecret, vaultSecret);
    }

    // ── MessageCipher44 round-trip ───────────────────────────────────────

    @Test
    void messageCipher44RoundTrip() {
        String plaintext = "Hello from KeyVaultIdentity via NIP-44!";

        // Alice encrypts to Bob
        MessageCipher44 encryptor =
                new MessageCipher44(identityAlice, identityBob.getPublicKey());
        String encrypted = encryptor.encrypt(plaintext);

        // Bob decrypts from Alice
        MessageCipher44 decryptor =
                new MessageCipher44(identityBob, identityAlice.getPublicKey());
        String decrypted = decryptor.decrypt(encrypted);

        assertEquals(plaintext, decrypted);
    }

    // ── GenericEvent signing ─────────────────────────────────────────────

    @Test
    void signGenericEvent() throws Exception { // SchnorrException
        GenericEvent event = GenericEvent.builder()
                .pubKey(identityAlice.getPublicKey())
                .kind(1)
                .content("vault-signed note")
                .build();

        Signature sig = identityAlice.sign(event);

        assertNotNull(sig);
        assertTrue(event.isSigned());
        assertEquals(64, event.getSignature().getRawData().length);

        // Verify the signature against the event's serialized id
        byte[] eventIdHash = NostrUtil.hexToBytes(event.getId());
        assertTrue(Schnorr.verify(eventIdHash,
                identityAlice.getPublicKey().getRawData(),
                event.getSignature().getRawData()));
    }

    // ── Test helpers ─────────────────────────────────────────────────────

    private static ISignable testSignable(byte[] data) {
        return new ISignable() {
            private Signature sig;

            @Override
            public Signature getSignature() { return sig; }

            @Override
            public void setSignature(Signature s) { this.sig = s; }

            @Override
            public Consumer<Signature> getSignatureConsumer() {
                return this::setSignature;
            }

            @Override
            public Supplier<ByteBuffer> getByteArraySupplier() {
                return () -> ByteBuffer.wrap(data);
            }
        };
    }
}
