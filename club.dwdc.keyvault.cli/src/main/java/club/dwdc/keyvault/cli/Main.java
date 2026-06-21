package club.dwdc.keyvault.cli;

import club.dwdc.keyvault.core.SeedStore;
import club.dwdc.keyvault.desktop.FileSeedStore;
import org.bitcoinj.wallet.DeterministicSeed;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.SecureRandom;

/**
 * kv-cli — seed management CLI for KeyVault.
 *
 * <p>Commands:
 * <ul>
 *   <li>{@code seed generate} — generate 24-word BIP-39 mnemonic, prompt passphrase, store</li>
 *   <li>{@code seed import} — read mnemonic from stdin, validate, prompt passphrase, store</li>
 *   <li>{@code seed show} — print stored mnemonic</li>
 *   <li>{@code seed delete} — prompt confirmation, delete</li>
 *   <li>{@code seed exists} — exit 0 if exists, exit 1 if not</li>
 * </ul>
 */
public class Main {

    public static void main(String[] args) {
        SeedStore store = new FileSeedStore();
        int exitCode = run(args, store);
        System.exit(exitCode);
    }

    static int run(String[] args, SeedStore store) {
        if (args.length < 2 || !"seed".equals(args[0])) {
            System.err.println("Usage: kv-cli seed <generate|import|show|delete|exists>");
            return 1;
        }

        BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
        String verb = args[1];
        return switch (verb) {
            case "generate" -> seedGenerate(store, stdin);
            case "import" -> seedImport(store, stdin);
            case "show" -> seedShow(store);
            case "delete" -> seedDelete(store, stdin);
            case "exists" -> store.exists() ? 0 : 1;
            default -> {
                System.err.println("Unknown command: seed " + verb);
                yield 1;
            }
        };
    }

    private static int seedGenerate(SeedStore store, BufferedReader stdin) {
        DeterministicSeed ds = DeterministicSeed.ofRandom(new SecureRandom(), 256, "");
        String mnemonic = ds.getMnemonicString();
        System.out.println(mnemonic);

        String passphrase = readPassphrase(stdin);
        store.store(mnemonic, passphrase);
        System.err.println("Seed stored.");
        return 0;
    }

    private static int seedImport(SeedStore store, BufferedReader stdin) {
        String mnemonic = readLine(stdin);
        if (mnemonic.isBlank()) {
            System.err.println("No mnemonic provided.");
            return 1;
        }

        try {
            DeterministicSeed.ofMnemonic(mnemonic, "").check();
        } catch (Exception e) {
            System.err.println("Invalid BIP-39 mnemonic: " + e.getMessage());
            return 1;
        }

        String passphrase = readPassphrase(stdin);
        store.store(mnemonic, passphrase);
        System.err.println("Seed stored.");
        return 0;
    }

    private static int seedShow(SeedStore store) {
        if (!store.exists()) {
            System.err.println("No seed stored.");
            return 1;
        }
        System.out.println(store.getMnemonic());
        return 0;
    }

    private static int seedDelete(SeedStore store, BufferedReader stdin) {
        if (!store.exists()) {
            System.err.println("No seed stored.");
            return 1;
        }
        System.err.print("Are you sure? (yes/no): ");
        String answer = readLine(stdin);
        if (!"yes".equals(answer)) {
            System.err.println("Aborted.");
            return 1;
        }
        store.delete();
        System.err.println("Seed deleted.");
        return 0;
    }

    private static String readPassphrase(BufferedReader fallback) {
        Console console = System.console();
        if (console != null) {
            char[] chars = console.readPassword("Passphrase (empty for none): ");
            return chars == null ? "" : new String(chars);
        }
        System.err.print("Passphrase (empty for none): ");
        return readLine(fallback);
    }

    private static String readLine(BufferedReader reader) {
        try {
            String line = reader.readLine();
            return line == null ? "" : line;
        } catch (IOException e) {
            return "";
        }
    }
}
