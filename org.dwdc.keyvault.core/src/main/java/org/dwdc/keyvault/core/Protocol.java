package org.dwdc.keyvault.core;

public enum Protocol {
    BITCOIN(0),
    NOSTR(1237),
    SSH(1238),
    OPENPGP(1239),
    X509(1240),
    WIREGUARD(1241);

    private final int coinType;

    Protocol(int coinType) {
        this.coinType = coinType;
    }

    public int coinType() {
        return coinType;
    }
}
