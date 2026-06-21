package club.dwdc.keyvault.cli;

import club.dwdc.keyvault.desktop.FileSeedStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class MainTest {

    private static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    private void setStdin(String input) {
        System.setIn(new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void seedGenerateStoresSeed(@TempDir Path tempDir) {
        // Provide empty passphrase via stdin
        setStdin("\n");
        FileSeedStore store = new FileSeedStore(tempDir);
        int exit = Main.run(new String[]{"seed", "generate"}, store);
        assertEquals(0, exit);
        assertTrue(store.exists());
        assertFalse(store.getMnemonic().isBlank());
        // 24-word mnemonic = 23 spaces
        assertEquals(23, store.getMnemonic().chars().filter(c -> c == ' ').count());
    }

    @Test
    void seedImportValidMnemonic(@TempDir Path tempDir) {
        setStdin(TEST_MNEMONIC + "\n\n");
        FileSeedStore store = new FileSeedStore(tempDir);
        int exit = Main.run(new String[]{"seed", "import"}, store);
        assertEquals(0, exit);
        assertTrue(store.exists());
        assertEquals(TEST_MNEMONIC, store.getMnemonic());
    }

    @Test
    void seedImportInvalidMnemonic(@TempDir Path tempDir) {
        setStdin("not a valid mnemonic\n");
        FileSeedStore store = new FileSeedStore(tempDir);
        int exit = Main.run(new String[]{"seed", "import"}, store);
        assertEquals(1, exit);
        assertFalse(store.exists());
    }

    @Test
    void seedShowPrintsMnemonic(@TempDir Path tempDir) {
        FileSeedStore store = new FileSeedStore(tempDir);
        store.store(TEST_MNEMONIC, "");
        int exit = Main.run(new String[]{"seed", "show"}, store);
        assertEquals(0, exit);
    }

    @Test
    void seedShowWhenNoSeed(@TempDir Path tempDir) {
        FileSeedStore store = new FileSeedStore(tempDir);
        int exit = Main.run(new String[]{"seed", "show"}, store);
        assertEquals(1, exit);
    }

    @Test
    void seedExistsReturnsZero(@TempDir Path tempDir) {
        FileSeedStore store = new FileSeedStore(tempDir);
        store.store(TEST_MNEMONIC, "");
        int exit = Main.run(new String[]{"seed", "exists"}, store);
        assertEquals(0, exit);
    }

    @Test
    void seedExistsReturnsOne(@TempDir Path tempDir) {
        FileSeedStore store = new FileSeedStore(tempDir);
        int exit = Main.run(new String[]{"seed", "exists"}, store);
        assertEquals(1, exit);
    }

    @Test
    void seedDeleteRemovesSeed(@TempDir Path tempDir) {
        setStdin("yes\n");
        FileSeedStore store = new FileSeedStore(tempDir);
        store.store(TEST_MNEMONIC, "");
        int exit = Main.run(new String[]{"seed", "delete"}, store);
        assertEquals(0, exit);
        assertFalse(store.exists());
    }

    @Test
    void unknownCommandReturnsOne(@TempDir Path tempDir) {
        FileSeedStore store = new FileSeedStore(tempDir);
        int exit = Main.run(new String[]{"seed", "bogus"}, store);
        assertEquals(1, exit);
    }
}
