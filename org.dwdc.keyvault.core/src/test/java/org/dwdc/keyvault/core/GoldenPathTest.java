package org.dwdc.keyvault.core;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * BIP-44 spec example paths with pinned hex output.
 * Uses the "all abandon" mnemonic. Golden hex values are regression guards —
 * if derivation logic changes, these break.
 */
class GoldenPathTest {

    private static final String MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    private static final int H = 0x80000000;
    private static final int SSH = Protocol.SSH.coinType();
    private static final int X509 = Protocol.X509.coinType();
    private static final HexFormat HEX = HexFormat.of();

    private final Bip32KeyDerivator kd = new Bip32KeyDerivator(MNEMONIC);

    private String deriveHex(int... path) {
        return HEX.formatHex(kd.derive(path));
    }

    // ── Golden paths ───────────────────────────────────────────────────

    /** m/44'/1237'/0'/0'/0' — Nostr default identity, Schnorr, index 0 */
    @Test
    void nostrDefault() {
        String hex = deriveHex(44 | H, 1237 | H, 0 | H, 0 | H, 0 | H);
        assertEquals("4f2d32ade6250539bb989a7cffd1d5ec882d16864f502632b6d4f087591f0ee1", hex);
    }

    /** m/44'/0'/0'/0'/0' — Bitcoin default, Schnorr, receive */
    @Test
    void bitcoinDefault() {
        String hex = deriveHex(44 | H, 0 | H, 0 | H, 0 | H, 0 | H);
        assertEquals("9138aa040b219a14ef56d98c7c587b9bb02a02015c870cf9c2dbfc333a295be0", hex);
    }

    /** m/44'/0'/0'/0x00000001'/0' — Bitcoin change address */
    @Test
    void bitcoinChange() {
        String hex = deriveHex(44 | H, 0 | H, 0 | H, 0x00000001 | H, 0 | H);
        assertEquals("24ed19a7ca741bd91b3b16b2460565bf24b08820794b56e6f9bb6367a8806fee", hex);
    }

    /** m/44'/1238'/0'/0x00010000'/0' — SSH Ed25519 user-auth */
    @Test
    void sshEd25519UserAuth() {
        String hex = deriveHex(44 | H, SSH | H, 0 | H, 0x00010000 | H, 0 | H);
        assertEquals("fa86e58223df8bd86ec4492877b0b5d9320bbf815707d2c8509d82ee16a2ba79", hex);
    }

    /** m/44'/1238'/0'/0x00010001'/0' — SSH Ed25519 host-key */
    @Test
    void sshEd25519HostKey() {
        String hex = deriveHex(44 | H, SSH | H, 0 | H, 0x00010001 | H, 0 | H);
        assertEquals("a74ae7ed77d30c3d5af969e95ebb6bda5a5dbba34ed7b9ec8a5b88a7a1d27679", hex);
    }

    /** m/44'/1238'/0'/0x00021000'/0x01000000' — SSH RSA-4096, HMAC-DRBG */
    @Test
    void sshRsa4096() {
        String hex = deriveHex(44 | H, SSH | H, 0 | H, 0x00021000 | H, 0x01000000 | H);
        assertEquals("a7870d47351a00bc4ee32a18470aabebd096baefa26ce207eaaba4933e93c24a", hex);
    }

    /** m/44'/1240'/hash("corp.com")'/0x00020800'/0x01000001' — X.509 CA RSA-2048, rotated once */
    @Test
    void x509CaRsa2048Rotated() {
        int identity = Bip32KeyDerivator.mangle("corp.com");
        String hex = deriveHex(44 | H, X509 | H, identity | H, 0x00020800 | H, 0x01000001 | H);
        assertEquals("ddd68faa981ac19aa9e00b75d040a997b97ea62e1e7df36dc7b438c2e92594cd", hex);
    }

    /** m/44'/1238'/mangle("alice@atlanta.com")'/0x00010000'/0' — SSH with named identity */
    @Test
    void sshNamedIdentity() {
        int identity = Bip32KeyDerivator.mangle("alice@atlanta.com");
        String hex = deriveHex(44 | H, SSH | H, identity | H, 0x00010000 | H, 0 | H);
        assertEquals("11137dbe0698580e6a9f6d1efe50a8ca0ec547ba08d2b3d037964d2e6c2e5911", hex);
    }

    // ── Cross-protocol / role isolation ─────────────────────────────────

    /** Nostr default vs Bitcoin default → different keys */
    @Test
    void nostrDefaultVsBitcoinDefault() {
        byte[] nostr   = kd.derive(44 | H, 1237 | H, 0 | H, 0 | H, 0 | H);
        byte[] bitcoin = kd.derive(44 | H, 0 | H,    0 | H, 0 | H, 0 | H);
        assertFalse(java.util.Arrays.equals(nostr, bitcoin),
                "Nostr and Bitcoin default paths must produce different keys");
    }

    /** SSH user-auth vs host-key (same identity, different role) → different keys */
    @Test
    void sshUserAuthVsHostKey() {
        byte[] userAuth = kd.derive(44 | H, SSH | H, 0 | H, 0x00010000 | H, 0 | H);
        byte[] hostKey  = kd.derive(44 | H, SSH | H, 0 | H, 0x00010001 | H, 0 | H);
        assertFalse(java.util.Arrays.equals(userAuth, hostKey),
                "SSH user-auth and host-key paths must produce different keys");
    }
}
