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
}
