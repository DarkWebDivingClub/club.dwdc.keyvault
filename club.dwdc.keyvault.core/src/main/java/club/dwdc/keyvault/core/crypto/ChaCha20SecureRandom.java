package club.dwdc.keyvault.core.crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.security.SecureRandom;

public class ChaCha20SecureRandom extends SecureRandom {
    private static final int KEY_SIZE = 32;
    private static final int NONCE_SIZE = 8;
    private static final int BLOCK_SIZE = 64;

    private final ChaChaEngine chaCha20Engine;
    private final byte[] nonce;

    public ChaCha20SecureRandom(byte[] seed) {
        if (seed.length < KEY_SIZE) {
            throw new IllegalArgumentException("Seed must be at least " + KEY_SIZE + " bytes.");
        }

        byte[] key = new byte[KEY_SIZE];
        nonce = new byte[NONCE_SIZE];

        SHA256Digest sha256 = new SHA256Digest();
        sha256.update(seed, 0, seed.length);
        sha256.doFinal(key, 0);

        System.arraycopy(seed, 0, nonce, 0, NONCE_SIZE);

        chaCha20Engine = new ChaChaEngine();
        chaCha20Engine.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
    }

    @Override
    public void nextBytes(byte[] bytes) {
        int offset = 0;
        while (offset < bytes.length) {
            byte[] block = new byte[BLOCK_SIZE];
            chaCha20Engine.processBytes(block, 0, BLOCK_SIZE, block, 0);

            nonce[7]++;
            if (nonce[7] == 0) {
                nonce[6]++;
            }

            int blockSize = Math.min(bytes.length - offset, BLOCK_SIZE);
            System.arraycopy(block, 0, bytes, offset, blockSize);
            offset += blockSize;
        }
    }
}
