package club.dwdc.keyvault.desktop;

import club.dwdc.keyvault.core.SeedStore;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Set;

/**
 * File-based seed storage for desktop systems.
 *
 * <p>Stores the BIP-39 mnemonic and optional passphrase in a plain-text file
 * at {@code $KV_HOME/seed} (default: {@code ~/.config/keyvault/seed}).
 * The directory is created with mode 0700 and the file with mode 0600.
 */
public class FileSeedStore implements SeedStore {

    private static final Set<PosixFilePermission> DIR_PERMS =
            PosixFilePermissions.fromString("rwx------");
    private static final Set<PosixFilePermission> FILE_PERMS =
            PosixFilePermissions.fromString("rw-------");

    private final Path seedPath;

    /** Create using default path: {@code $KV_HOME/seed} or {@code ~/.config/keyvault/seed}. */
    public FileSeedStore() {
        this(defaultBaseDir());
    }

    /** Create using the given base directory (useful for testing with {@code @TempDir}). */
    public FileSeedStore(Path baseDir) {
        this.seedPath = baseDir.resolve("seed");
    }

    @Override
    public boolean exists() {
        return Files.exists(seedPath);
    }

    @Override
    public void store(String mnemonic, String passphrase) {
        try {
            Path dir = seedPath.getParent();
            if (!Files.exists(dir)) {
                Files.createDirectories(dir);
                Files.setPosixFilePermissions(dir, DIR_PERMS);
            }
            Files.writeString(seedPath, mnemonic + "\n" + passphrase + "\n");
            Files.setPosixFilePermissions(seedPath, FILE_PERMS);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to store seed", e);
        }
    }

    @Override
    public String getMnemonic() {
        if (!exists()) {
            throw new IllegalStateException("No seed stored at " + seedPath);
        }
        try {
            List<String> lines = Files.readAllLines(seedPath);
            return lines.get(0);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read seed", e);
        }
    }

    @Override
    public String getPassphrase() {
        if (!exists()) {
            throw new IllegalStateException("No seed stored at " + seedPath);
        }
        try {
            List<String> lines = Files.readAllLines(seedPath);
            if (lines.size() < 2 || lines.get(1).isEmpty()) {
                return "";
            }
            return lines.get(1);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read seed", e);
        }
    }

    @Override
    public void delete() {
        try {
            Files.deleteIfExists(seedPath);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to delete seed", e);
        }
    }

    private static Path defaultBaseDir() {
        String kvHome = System.getenv("KV_HOME");
        if (kvHome != null && !kvHome.isEmpty()) {
            return Path.of(kvHome);
        }
        return Path.of(System.getProperty("user.home"), ".config", "keyvault");
    }
}
