package club.dwdc.keyvault.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MangleTest {

    // ── 2.1 Determinism ────────────────────────────────────────────────

    @Test
    void sameInputSameOutput() {
        assertEquals(
                Bip32KeyDerivator.mangle("alice@home.com"),
                Bip32KeyDerivator.mangle("alice@home.com"));
    }

    // ── 2.2 Sensitivity ────────────────────────────────────────────────

    @Test
    void differentInputsDiffer() {
        assertNotEquals(
                Bip32KeyDerivator.mangle("alice@home.com"),
                Bip32KeyDerivator.mangle("bob@home.com"));
    }

    @Test
    void caseSensitive() {
        assertNotEquals(
                Bip32KeyDerivator.mangle("Alice"),
                Bip32KeyDerivator.mangle("alice"));
    }

    @Test
    void emptyVsNonEmpty() {
        assertNotEquals(
                Bip32KeyDerivator.mangle(""),
                Bip32KeyDerivator.mangle("a"));
    }

    @Test
    void similarStringsDiffer() {
        assertNotEquals(
                Bip32KeyDerivator.mangle("test1"),
                Bip32KeyDerivator.mangle("test2"));
    }

    @Test
    void unicodeDiffers() {
        assertNotEquals(
                Bip32KeyDerivator.mangle("caf\u00e9"),
                Bip32KeyDerivator.mangle("cafe"));
    }

    // ── 2.3 Bit range ──────────────────────────────────────────────────

    @Test
    void resultIs31Bit() {
        String[] inputs = {"alice@home.com", "bob@home.com", "", "test", "xyz123"};
        for (String input : inputs) {
            int val = Bip32KeyDerivator.mangle(input);
            assertTrue(val <= 0x7FFFFFFF,
                    "mangle(\"" + input + "\") = " + val + " exceeds 31-bit range");
        }
    }

    @Test
    void resultIsNonNegative() {
        String[] inputs = {"alice@home.com", "bob@home.com", "", "test", "xyz123"};
        for (String input : inputs) {
            int val = Bip32KeyDerivator.mangle(input);
            assertTrue(val >= 0,
                    "mangle(\"" + input + "\") = " + val + " is negative");
        }
    }

    @Test
    void emptyStringProduces31Bit() {
        int val = Bip32KeyDerivator.mangle("");
        assertTrue(val >= 0 && val <= 0x7FFFFFFF);
    }

    @Test
    void longStringProduces31Bit() {
        String longStr = "x".repeat(1000);
        int val = Bip32KeyDerivator.mangle(longStr);
        assertTrue(val >= 0 && val <= 0x7FFFFFFF);
    }

    // ── 2.4 Known value ────────────────────────────────────────────────

    @Test
    void knownSha256TruncationValue() {
        // SHA-256("alice@atlanta.com") first 4 bytes → 31-bit int
        // Pinned so any algorithm change is caught.
        int actual = Bip32KeyDerivator.mangle("alice@atlanta.com");
        assertEquals(0x748b0a69, actual,
                () -> "mangle(\"alice@atlanta.com\") = 0x"
                        + Integer.toHexString(actual) + " did not match pinned value");
    }

    // ── 2.5 Cross-language (T2) ─────────────────────────────────────────
    // These values must match the Rust protocol_index() tests exactly.

    @Test
    void t2_crossLanguageSsh() {
        int val = Bip32KeyDerivator.mangle("ssh");
        assertEquals(0x7f5a55cf, val,
                () -> "mangle(\"ssh\") = 0x" + Integer.toHexString(val));
    }

    @Test
    void t2_crossLanguageGpg() {
        int val = Bip32KeyDerivator.mangle("gpg");
        assertEquals(0x6858a423, val,
                () -> "mangle(\"gpg\") = 0x" + Integer.toHexString(val));
    }

    @Test
    void t2_crossLanguageNostr() {
        int val = Bip32KeyDerivator.mangle("nostr");
        assertEquals(0x0f5392e4, val,
                () -> "mangle(\"nostr\") = 0x" + Integer.toHexString(val));
    }

    // ── 2.6 deriveXpub / deriveKey ──────────────────────────────────────

    @Test
    void deriveXpubProducesValidFormat() {
        byte[] seed = new byte[64]; // all zeros
        seed[0] = 1;
        Bip32KeyDerivator kd = new Bip32KeyDerivator(seed);
        String xpub = kd.deriveXpub(0);
        assertTrue(xpub.startsWith("xpub"), "xpub must start with 'xpub': " + xpub);
    }

    @Test
    void deriveKeyRoundTrip() {
        byte[] seed = new byte[64];
        seed[0] = 1;
        Bip32KeyDerivator kd = new Bip32KeyDerivator(seed);
        var key = kd.deriveKey(0);
        byte[] privBytes = key.getPrivKeyBytes();
        assertNotNull(privBytes);
        assertEquals(32, privBytes.length);
    }
}
