package org.dwdc.keyvault.core;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ProtocolTest {

    @Test
    void bitcoinCoinType() {
        assertEquals(0, Protocol.BITCOIN.coinType());
    }

    @Test
    void nostrCoinType() {
        assertEquals(1237, Protocol.NOSTR.coinType());
    }

    @Test
    void sshCoinType() {
        assertEquals(1238, Protocol.SSH.coinType());
    }

    @Test
    void openPgpCoinType() {
        assertEquals(1239, Protocol.OPENPGP.coinType());
    }

    @Test
    void x509CoinType() {
        assertEquals(1240, Protocol.X509.coinType());
    }

    @Test
    void wireGuardCoinType() {
        assertEquals(1241, Protocol.WIREGUARD.coinType());
    }

    @Test
    void allCoinTypesUnique() {
        Set<Integer> seen = new HashSet<>();
        for (Protocol p : Protocol.values()) {
            assertTrue(seen.add(p.coinType()),
                    "Duplicate coin type " + p.coinType() + " for " + p);
        }
    }

    @Test
    void allCoinTypes31Bit() {
        for (Protocol p : Protocol.values()) {
            int ct = p.coinType();
            assertTrue(ct >= 0 && ct <= 0x7FFFFFFF,
                    p + ".coinType() = " + ct + " is out of 31-bit range");
        }
    }
}
