package com.tripledesencryptor.app;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * Interactive menu around {@link EncryptionManager}.
 */
public class App {

    private interface IOptionExecute {
        void execute(String password) throws Exception;
    }

    // All input comes from one source per run, so the two readers never compete for stdin.
    private static final Console CONSOLE = System.console();
    private static final BufferedReader STDIN =
            new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

    public static void main(String[] args) throws Exception {
        Map<String, IOptionExecute> availableOptions = new HashMap<>();
        availableOptions.put("1", (password) -> {
            boolean encrypt = "1".equals(readFromConsole("1. encrypt or 2. decrypt ?"));
            String word = readFromConsole("word?");
            if (encrypt) {
                String enc = EncryptionManager.encrypt(word, password);
                System.out.println("Encryption Result: " + enc);
                System.out.println("Decryption Result: " + EncryptionManager.decrypt(enc, password));
            } else {
                System.out.println("Decryption Result: " + EncryptionManager.decrypt(word, password));
            }
        });
        availableOptions.put("2", (password) -> EncryptionManager.encryptFile(
                Paths.get(readFromConsole("Path to read?")),
                Paths.get(readFromConsole("Path to write?")),
                password));
        availableOptions.put("3", (password) -> EncryptionManager.decryptFile(
                Paths.get(readFromConsole("Path to read?")),
                Paths.get(readFromConsole("Path to write?")),
                password));

        String choice;
        while (availableOptions.containsKey(choice = readFromConsole(getUsage()))) {
            try {
                availableOptions.get(choice).execute(readPassword());
            } catch (Exception ex) {
                System.out.println("Failed: " + describe(ex));
            }
        }
        System.out.println("Goodbye...");
    }

    private static String describe(Exception ex) {
        if (ex instanceof javax.crypto.AEADBadTagException) {
            return "wrong password, or the data was modified.";
        }
        return ex.getClass().getSimpleName() + ": " + ex.getMessage();
    }

    /** Reads the password without echo when a terminal is attached, from stdin otherwise. */
    private static String readPassword() throws IOException {
        System.out.println("Pass?");
        if (CONSOLE != null) {
            char[] chars = CONSOLE.readPassword();
            return chars == null ? null : new String(chars);
        }
        return STDIN.readLine();
    }

    private static String readFromConsole(String message) throws IOException {
        System.out.println(message);
        return CONSOLE != null ? CONSOLE.readLine() : STDIN.readLine();
    }

    private static String getUsage() {
        return "Usage:\n1. String encryption & decryption\n2. File encryption\n3. File decryption";
    }

}
