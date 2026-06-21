package club.dwdc.keyvault.desktop;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class FileSeedStoreTest {

    private static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    @Test
    void storeAndLoadMnemonic(@TempDir Path tempDir) {
        FileSeedStore store = new FileSeedStore(tempDir);
        store.store(TEST_MNEMONIC, "");
        assertEquals(TEST_MNEMONIC, store.getMnemonic());
    }

    @Test
    void storeAndLoadPassphrase(@TempDir Path tempDir) {
        FileSeedStore store = new FileSeedStore(tempDir);
        store.store(TEST_MNEMONIC, "my-secret");
        assertEquals("my-secret", store.getPassphrase());
    }

    @Test
    void emptyPassphraseReturnsEmptyString(@TempDir Path tempDir) {
        FileSeedStore store = new FileSeedStore(tempDir);
        store.store(TEST_MNEMONIC, "");
        assertEquals("", store.getPassphrase());
    }

    @Test
    void existsReturnsFalseBeforeStore(@TempDir Path tempDir) {
        FileSeedStore store = new FileSeedStore(tempDir);
        assertFalse(store.exists());
    }

    @Test
    void existsReturnsTrueAfterStore(@TempDir Path tempDir) {
        FileSeedStore store = new FileSeedStore(tempDir);
        store.store(TEST_MNEMONIC, "");
        assertTrue(store.exists());
    }

    @Test
    void deleteRemovesSeed(@TempDir Path tempDir) {
        FileSeedStore store = new FileSeedStore(tempDir);
        store.store(TEST_MNEMONIC, "");
        assertTrue(store.exists());
        store.delete();
        assertFalse(store.exists());
    }

    @Test
    void getMnemonicThrowsWhenNoSeed(@TempDir Path tempDir) {
        FileSeedStore store = new FileSeedStore(tempDir);
        assertThrows(IllegalStateException.class, store::getMnemonic);
    }

    @Test
    void filePermissionsAre0600(@TempDir Path tempDir) throws IOException {
        FileSeedStore store = new FileSeedStore(tempDir);
        store.store(TEST_MNEMONIC, "");
        Set<PosixFilePermission> perms = Files.getPosixFilePermissions(tempDir.resolve("seed"));
        assertEquals(PosixFilePermissions.fromString("rw-------"), perms);
    }

    @Test
    void storeOverwritesExisting(@TempDir Path tempDir) {
        FileSeedStore store = new FileSeedStore(tempDir);
        store.store("first mnemonic", "pass1");
        store.store(TEST_MNEMONIC, "pass2");
        assertEquals(TEST_MNEMONIC, store.getMnemonic());
        assertEquals("pass2", store.getPassphrase());
    }
}
