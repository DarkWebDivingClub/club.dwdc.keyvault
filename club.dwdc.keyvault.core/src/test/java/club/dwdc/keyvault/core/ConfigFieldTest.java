package club.dwdc.keyvault.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ConfigFieldTest {

    // ── 4.1 Known values from spec ─────────────────────────────────────

    @Test
    void noneIndex0() {
        assertEquals(0x00000000, new ConfigField(0, 0).toIndex());
    }

    @Test
    void hmacDrbgIndex0() {
        assertEquals(0x01000000, new ConfigField(1, 0).toIndex());
    }

    @Test
    void hmacDrbgIndex1() {
        assertEquals(0x01000001, new ConfigField(1, 1).toIndex());
    }

    @Test
    void ctrDrbgIndex0() {
        assertEquals(0x02000000, new ConfigField(2, 0).toIndex());
    }

    @Test
    void chacha20Index0() {
        assertEquals(0x03000000, new ConfigField(3, 0).toIndex());
    }

    // ── 4.2 Boundary values ────────────────────────────────────────────

    @Test
    void cfgZero() {
        assertEquals(0, new ConfigField(0, 0).toIndex());
    }

    @Test
    void cfgMaxCsprng() {
        assertEquals(0x7F000000, new ConfigField(0x7F, 0).toIndex());
    }

    @Test
    void cfgMaxIndex() {
        assertEquals(0x00FFFFFF, new ConfigField(0, 0xFFFFFF).toIndex());
    }

    @Test
    void cfgAllMax() {
        assertEquals(0x7FFFFFFF, new ConfigField(0x7F, 0xFFFFFF).toIndex());
    }

    @Test
    void cfgOne() {
        assertEquals(0x01000001, new ConfigField(1, 1).toIndex());
    }

    // ── 4.3 Masking / overflow ─────────────────────────────────────────

    @Test
    void csprngOverflowIsMasked() {
        assertEquals(0, new ConfigField(0x80, 0).toIndex());
    }

    @Test
    void indexOverflowIsMasked() {
        assertEquals(0, new ConfigField(0, 0x1000000).toIndex());
    }

    // ── 4.4 Field isolation ────────────────────────────────────────────

    @Test
    void changingCsprngOnly() {
        assertNotEquals(
                new ConfigField(0, 0).toIndex(),
                new ConfigField(1, 0).toIndex());
    }

    @Test
    void changingIndexOnly() {
        assertNotEquals(
                new ConfigField(1, 0).toIndex(),
                new ConfigField(1, 1).toIndex());
    }

    @Test
    void noFieldOverlap() {
        // max csprng doesn't bleed into index
        int maxCsprng = new ConfigField(0x7F, 0).toIndex();
        assertEquals(0, maxCsprng & 0x00FFFFFF, "max csprng bleeds into index");

        // max index doesn't bleed into csprng
        int maxIndex = new ConfigField(0, 0xFFFFFF).toIndex();
        assertEquals(0, maxIndex & 0x7F000000, "max index bleeds into csprng");
    }
}
