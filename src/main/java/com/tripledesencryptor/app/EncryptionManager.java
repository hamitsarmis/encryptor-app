package com.tripledesencryptor.app;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Password-based authenticated encryption: AES-256-GCM with a key derived by
 * PBKDF2-HMAC-SHA256. Uses only the JCA providers shipped with the JDK.
 *
 * <p>Every message is serialised as {@code salt || iv || ciphertext+tag}:
 * 16 bytes of salt, 12 bytes of IV, then the ciphertext with its 16-byte tag.
 * The string methods wrap that in Base64; the byte and file methods do not.
 */
public final class EncryptionManager {

    static final int SALT_LENGTH = 16;
    static final int IV_LENGTH = 12;
    static final int TAG_LENGTH_BITS = 128;
    static final int KEY_LENGTH_BITS = 256;
    static final int PBKDF2_ITERATIONS = 600_000;

    private static final String CIPHER = "AES/GCM/NoPadding";
    private static final String KEY_DERIVATION = "PBKDF2WithHmacSHA256";
    private static final int HEADER_LENGTH = SALT_LENGTH + IV_LENGTH;
    private static final int MIN_LENGTH = HEADER_LENGTH + TAG_LENGTH_BITS / 8;
    private static final SecureRandom RANDOM = new SecureRandom();

    private EncryptionManager() {
    }

    /**
     * Encrypts a string (as UTF-8) and returns Base64 of
     * {@code salt || iv || ciphertext+tag}.
     */
    public static String encrypt(String message, String pass) throws GeneralSecurityException {
        byte[] encrypted = encrypt(message.getBytes(StandardCharsets.UTF_8), pass);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Reverses {@link #encrypt(String, String)}.
     *
     * @throws javax.crypto.AEADBadTagException if the password is wrong or the data was modified
     * @throws IllegalArgumentException if the input is not Base64 or is too short
     */
    public static String decrypt(String message, String pass) throws GeneralSecurityException {
        byte[] decrypted = decrypt(Base64.getDecoder().decode(message), pass);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     * Encrypts bytes under a fresh random salt and IV and returns
     * {@code salt || iv || ciphertext+tag}.
     */
    public static byte[] encrypt(byte[] input, String pass) throws GeneralSecurityException {
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        RANDOM.nextBytes(salt);
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(pass, salt), new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        byte[] ciphertext = cipher.doFinal(input);

        byte[] output = new byte[HEADER_LENGTH + ciphertext.length];
        System.arraycopy(salt, 0, output, 0, SALT_LENGTH);
        System.arraycopy(iv, 0, output, SALT_LENGTH, IV_LENGTH);
        System.arraycopy(ciphertext, 0, output, HEADER_LENGTH, ciphertext.length);
        return output;
    }

    /**
     * Reverses {@link #encrypt(byte[], String)}.
     *
     * @throws javax.crypto.AEADBadTagException if the password is wrong or any byte was modified
     * @throws IllegalArgumentException if the input is shorter than salt, IV and tag together
     */
    public static byte[] decrypt(byte[] input, String pass) throws GeneralSecurityException {
        if (input.length < MIN_LENGTH) {
            throw new IllegalArgumentException(
                    "Input is " + input.length + " bytes; an encrypted message is at least " + MIN_LENGTH + ".");
        }
        byte[] salt = Arrays.copyOfRange(input, 0, SALT_LENGTH);
        byte[] iv = Arrays.copyOfRange(input, SALT_LENGTH, HEADER_LENGTH);

        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(pass, salt), new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        return cipher.doFinal(input, HEADER_LENGTH, input.length - HEADER_LENGTH);
    }

    /** Encrypts a whole file into {@code target} as raw {@code salt || iv || ciphertext+tag}. */
    public static void encryptFile(Path source, Path target, String pass)
            throws GeneralSecurityException, IOException {
        Files.write(target, encrypt(Files.readAllBytes(source), pass));
    }

    /**
     * Decrypts a file written by {@link #encryptFile}. The tag is verified
     * before {@code target} is created, so a failed decryption writes nothing.
     */
    public static void decryptFile(Path source, Path target, String pass)
            throws GeneralSecurityException, IOException {
        Files.write(target, decrypt(Files.readAllBytes(source), pass));
    }

    private static SecretKeySpec deriveKey(String pass, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(pass.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS);
        try {
            byte[] keyBytes = SecretKeyFactory.getInstance(KEY_DERIVATION).generateSecret(spec).getEncoded();
            try {
                return new SecretKeySpec(keyBytes, "AES");
            } finally {
                Arrays.fill(keyBytes, (byte) 0);
            }
        } finally {
            spec.clearPassword();
        }
    }
}
