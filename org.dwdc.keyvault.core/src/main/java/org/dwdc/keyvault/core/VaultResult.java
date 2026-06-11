package org.dwdc.keyvault.core;

/**
 * Result of a vault operation. Carries a numeric status code
 * and the output bytes. Status 0 = success; non-zero = error.
 */
public record VaultResult(int status, byte[] data) {

    /** Operation completed successfully. */
    public static final int OK = 0;

    /** The requested function code is not supported. */
    public static final int ERR_UNSUPPORTED_FUNCTION = 1;

    /** The derivation path is invalid or incomplete. */
    public static final int ERR_INVALID_PATH = 2;

    /** The payload is missing or malformed for this function. */
    public static final int ERR_INVALID_PAYLOAD = 3;

    /** The algorithm in the path is not supported by this implementation. */
    public static final int ERR_UNSUPPORTED_ALGORITHM = 4;

    /** A cryptographic operation failed (e.g. signing error). */
    public static final int ERR_CRYPTO_FAILURE = 5;

    public boolean isOk() {
        return status == OK;
    }

    public static VaultResult ok(byte[] data) {
        return new VaultResult(OK, data);
    }

    public static VaultResult error(int status) {
        return new VaultResult(status, null);
    }
}
