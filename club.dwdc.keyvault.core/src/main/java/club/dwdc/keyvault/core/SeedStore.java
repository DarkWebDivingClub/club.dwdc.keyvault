package club.dwdc.keyvault.core;

/**
 * Seed lifecycle management — store, load, and delete BIP-39 mnemonics.
 *
 * <p>Implementations provide platform-specific storage (file system, encrypted
 * preferences, etc.). The mnemonic and optional passphrase are the only
 * secrets managed by this interface.
 */
public interface SeedStore {

    /** Check whether a seed exists in storage. */
    boolean exists();

    /** Store a mnemonic and passphrase. Overwrites if exists. */
    void store(String mnemonic, String passphrase);

    /** Load the stored mnemonic. Throws if {@code !exists()}. */
    String getMnemonic();

    /** Load the stored passphrase. Returns {@code ""} if none set. */
    String getPassphrase();

    /** Delete the stored seed permanently. */
    void delete();
}
