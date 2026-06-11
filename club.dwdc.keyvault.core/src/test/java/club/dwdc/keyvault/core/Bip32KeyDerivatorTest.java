package club.dwdc.keyvault.core;

import org.bitcoinj.wallet.DeterministicSeed;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class Bip32KeyDerivatorTest {

    private static final String MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    private static final String MNEMONIC_2 =
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

    private static final int H = 0x80000000;

    // ── 1.1 Determinism ────────────────────────────────────────────────

    @Test
    void samePathProducesSameKey() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        int[] path = {44 | H, 22 | H, 0 | H, 0x00010000 | H, 0 | H};
        assertArrayEquals(kd.derive(path), kd.derive(path));
    }

    @Test
    void samePathNewInstance() {
        var kd1 = new Bip32KeyDerivator(MNEMONIC);
        var kd2 = new Bip32KeyDerivator(MNEMONIC);
        int[] path = {44 | H, 22 | H, 0 | H, 0x00010000 | H, 0 | H};
        assertArrayEquals(kd1.derive(path), kd2.derive(path));
    }

    @Test
    void multipleCallsAreIdempotent() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        int[] path = {44 | H, 0 | H, 0 | H, 0 | H, 0 | H};
        byte[] first = kd.derive(path);
        for (int i = 0; i < 9; i++) {
            assertArrayEquals(first, kd.derive(path));
        }
    }

    // ── 1.2 Output format ──────────────────────────────────────────────

    @Test
    void outputIs32Bytes_depth0() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        assertEquals(32, kd.derive().length);
    }

    @Test
    void outputIs32Bytes_depth1() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        assertEquals(32, kd.derive(44 | H).length);
    }

    @Test
    void outputIs32Bytes_depth3() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        assertEquals(32, kd.derive(44 | H, 22 | H, 0 | H).length);
    }

    @Test
    void outputIs32Bytes_depth5() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        assertEquals(32, kd.derive(44 | H, 22 | H, 0 | H, 0 | H, 0 | H).length);
    }

    @Test
    void outputIsNonZero() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        byte[] key = kd.derive(44 | H, 22 | H, 0 | H, 0 | H, 0 | H);
        boolean allZero = true;
        for (byte b : key) {
            if (b != 0) { allZero = false; break; }
        }
        assertFalse(allZero, "Derived key must not be all zeros");
    }

    // ── 1.3 Path sensitivity — changing one level ──────────────────────

    @Test
    void changingLevel1ProducesDifferentKey() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        byte[] a = kd.derive(44 | H, 22 | H, 0 | H, 0 | H, 0 | H);
        byte[] b = kd.derive(89 | H, 22 | H, 0 | H, 0 | H, 0 | H);
        assertFalse(java.util.Arrays.equals(a, b));
    }

    @Test
    void changingLevel2ProducesDifferentKey() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        byte[] a = kd.derive(44 | H, 0 | H, 0 | H, 0 | H, 0 | H);
        byte[] b = kd.derive(44 | H, 22 | H, 0 | H, 0 | H, 0 | H);
        assertFalse(java.util.Arrays.equals(a, b));
    }

    @Test
    void changingLevel3ProducesDifferentKey() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        byte[] a = kd.derive(44 | H, 22 | H, 0 | H, 0 | H, 0 | H);
        byte[] b = kd.derive(44 | H, 22 | H, 1 | H, 0 | H, 0 | H);
        assertFalse(java.util.Arrays.equals(a, b));
    }

    @Test
    void changingLevel4ProducesDifferentKey() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        byte[] a = kd.derive(44 | H, 22 | H, 0 | H, 0x00010000 | H, 0 | H);
        byte[] b = kd.derive(44 | H, 22 | H, 0 | H, 0x00020000 | H, 0 | H);
        assertFalse(java.util.Arrays.equals(a, b));
    }

    @Test
    void changingLevel5ProducesDifferentKey() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        byte[] a = kd.derive(44 | H, 22 | H, 0 | H, 0 | H, 0 | H);
        byte[] b = kd.derive(44 | H, 22 | H, 0 | H, 0 | H, 1 | H);
        assertFalse(java.util.Arrays.equals(a, b));
    }

    // ── 1.4 Hardened vs non-hardened ───────────────────────────────────

    @Test
    void hardenedVsNonHardened_level1() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        byte[] hardened = kd.derive(44 | H, 22 | H, 0 | H, 0 | H, 0 | H);
        byte[] normal   = kd.derive(44,     22 | H, 0 | H, 0 | H, 0 | H);
        assertFalse(java.util.Arrays.equals(hardened, normal));
    }

    @Test
    void hardenedVsNonHardened_level2() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        byte[] hardened = kd.derive(44 | H, 22 | H, 0 | H, 0 | H, 0 | H);
        byte[] normal   = kd.derive(44 | H, 22,     0 | H, 0 | H, 0 | H);
        assertFalse(java.util.Arrays.equals(hardened, normal));
    }

    @Test
    void hardenedVsNonHardened_leaf() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        byte[] hardened = kd.derive(44 | H, 22 | H, 0 | H, 0 | H, 0 | H);
        byte[] normal   = kd.derive(44 | H, 22 | H, 0 | H, 0 | H, 0);
        assertFalse(java.util.Arrays.equals(hardened, normal));
    }

    @Test
    void allHardenedVsAllNonHardened() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        byte[] hardened = kd.derive(44 | H, 22 | H, 0 | H, 0 | H, 0 | H);
        byte[] normal   = kd.derive(44,     22,     0,     0,     0);
        assertFalse(java.util.Arrays.equals(hardened, normal));
    }

    // ── 1.5 Path structure ─────────────────────────────────────────────

    @Test
    void pathOrderMatters() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        byte[] ab = kd.derive(1 | H, 2 | H);
        byte[] ba = kd.derive(2 | H, 1 | H);
        assertFalse(java.util.Arrays.equals(ab, ba));
    }

    @Test
    void longerPathDiffersFromPrefix() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        byte[] abc = kd.derive(44 | H, 22 | H, 0 | H);
        byte[] ab  = kd.derive(44 | H, 22 | H);
        assertFalse(java.util.Arrays.equals(abc, ab));
    }

    @Test
    void appendingLevelChangesKey() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        byte[] a  = kd.derive(44 | H);
        byte[] a0 = kd.derive(44 | H, 0);
        assertFalse(java.util.Arrays.equals(a, a0));
    }

    @Test
    void singleChildZero() {
        var kd = new Bip32KeyDerivator(MNEMONIC);
        byte[] master = kd.derive();
        byte[] child0 = kd.derive(0);
        assertFalse(java.util.Arrays.equals(master, child0));
    }

    // ── 1.6 Constructor equivalence ────────────────────────────────────

    @Test
    void mnemonicAndSeedConstructorsAgree() {
        byte[] seed = DeterministicSeed.ofMnemonic(MNEMONIC, "").getSeedBytes();
        var fromMnemonic = new Bip32KeyDerivator(MNEMONIC);
        var fromSeed = new Bip32KeyDerivator(seed);
        int[] path = {44 | H, 22 | H, 0 | H, 0x00010000 | H, 0 | H};
        assertArrayEquals(fromMnemonic.derive(path), fromSeed.derive(path));
    }

    @Test
    void mnemonicAndSeedAgree_multipleDepths() {
        byte[] seed = DeterministicSeed.ofMnemonic(MNEMONIC, "").getSeedBytes();
        var fromMnemonic = new Bip32KeyDerivator(MNEMONIC);
        var fromSeed = new Bip32KeyDerivator(seed);

        // depth 1
        assertArrayEquals(
                fromMnemonic.derive(44 | H),
                fromSeed.derive(44 | H));
        // depth 3
        assertArrayEquals(
                fromMnemonic.derive(44 | H, 22 | H, 0 | H),
                fromSeed.derive(44 | H, 22 | H, 0 | H));
        // depth 5
        assertArrayEquals(
                fromMnemonic.derive(44 | H, 22 | H, 0 | H, 0 | H, 0 | H),
                fromSeed.derive(44 | H, 22 | H, 0 | H, 0 | H, 0 | H));
    }

    // ── 1.7 Different mnemonics ────────────────────────────────────────

    @Test
    void differentMnemonicProducesDifferentKey() {
        var kd1 = new Bip32KeyDerivator(MNEMONIC);
        var kd2 = new Bip32KeyDerivator(MNEMONIC_2);
        int[] path = {44 | H, 22 | H, 0 | H, 0x00010000 | H, 0 | H};
        assertFalse(java.util.Arrays.equals(kd1.derive(path), kd2.derive(path)));
    }
}
