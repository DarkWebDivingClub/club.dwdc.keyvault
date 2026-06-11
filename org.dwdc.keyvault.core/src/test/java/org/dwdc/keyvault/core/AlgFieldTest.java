package org.dwdc.keyvault.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AlgFieldTest {

    // ── 3.1 Known values from spec ─────────────────────────────────────

    @Test
    void schnorrDefault() {
        assertEquals(0x00000000, new AlgField(0, 0, 0).toIndex());
    }

    @Test
    void ed25519UserAuth() {
        assertEquals(0x00010000, new AlgField(1, 0, 0).toIndex());
    }

    @Test
    void ed25519HostKey() {
        assertEquals(0x00010001, new AlgField(1, 0, 1).toIndex());
    }

    @Test
    void rsaVariant16Role0() {
        assertEquals(0x00021000, new AlgField(2, 16, 0).toIndex());
    }

    @Test
    void rsaVariant8Role0() {
        assertEquals(0x00020800, new AlgField(2, 8, 0).toIndex());
    }

    @Test
    void ecdsaP256() {
        assertEquals(0x00030100, new AlgField(3, 1, 0).toIndex());
    }

    @Test
    void schnorrChangeRole() {
        assertEquals(0x00000001, new AlgField(0, 0, 1).toIndex());
    }

    // ── 3.2 Boundary values ────────────────────────────────────────────

    @Test
    void algZero() {
        assertEquals(0, new AlgField(0, 0, 0).toIndex());
    }

    @Test
    void algMaxAlg() {
        assertEquals(0x7FFF0000, new AlgField(0x7FFF, 0, 0).toIndex());
    }

    @Test
    void algMaxVariant() {
        assertEquals(0x0000FF00, new AlgField(0, 0xFF, 0).toIndex());
    }

    @Test
    void algMaxRole() {
        assertEquals(0x000000FF, new AlgField(0, 0, 0xFF).toIndex());
    }

    @Test
    void algAllMax() {
        assertEquals(0x7FFFFFFF, new AlgField(0x7FFF, 0xFF, 0xFF).toIndex());
    }

    @Test
    void algOne() {
        assertEquals(0x00010101, new AlgField(1, 1, 1).toIndex());
    }

    // ── 3.3 Masking / overflow ─────────────────────────────────────────

    @Test
    void algOverflowIsMasked() {
        assertEquals(0, new AlgField(0x8000, 0, 0).toIndex());
    }

    @Test
    void variantOverflowIsMasked() {
        assertEquals(0, new AlgField(0, 0x100, 0).toIndex());
    }

    @Test
    void roleOverflowIsMasked() {
        assertEquals(0, new AlgField(0, 0, 0x100).toIndex());
    }

    // ── 3.4 Field isolation ────────────────────────────────────────────

    @Test
    void changingAlgOnly() {
        assertNotEquals(
                new AlgField(0, 0, 0).toIndex(),
                new AlgField(1, 0, 0).toIndex());
    }

    @Test
    void changingVariantOnly() {
        assertNotEquals(
                new AlgField(1, 0, 0).toIndex(),
                new AlgField(1, 1, 0).toIndex());
    }

    @Test
    void changingRoleOnly() {
        assertNotEquals(
                new AlgField(1, 0, 0).toIndex(),
                new AlgField(1, 0, 1).toIndex());
    }

    @Test
    void noFieldOverlap() {
        // max alg doesn't bleed into variant/role
        int maxAlg = new AlgField(0x7FFF, 0, 0).toIndex();
        assertEquals(0, maxAlg & 0x0000FFFF, "max alg bleeds into variant/role");

        // max variant doesn't bleed into alg or role
        int maxVar = new AlgField(0, 0xFF, 0).toIndex();
        assertEquals(0, maxVar & 0x7FFF0000, "max variant bleeds into alg");
        assertEquals(0, maxVar & 0x000000FF, "max variant bleeds into role");

        // max role doesn't bleed into alg or variant
        int maxRole = new AlgField(0, 0, 0xFF).toIndex();
        assertEquals(0, maxRole & 0x7FFFFF00, "max role bleeds into alg/variant");
    }
}
