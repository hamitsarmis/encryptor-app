package com.tripledesencryptor.app;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.AEADBadTagException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EncryptionManagerTest {

    private static final String PASSWORD = "correct horse battery staple";
    private static final int SALT = 16;
    private static final int IV = 12;
    private static final int TAG = 16;

    @Test
    void stringRoundTrip() throws Exception {
        String message = "hello world, ğüşiöç €";

        String encrypted = EncryptionManager.encrypt(message, PASSWORD);

        assertEquals(message, EncryptionManager.decrypt(encrypted, PASSWORD));
    }

    @Test
    void emptyStringRoundTrip() throws Exception {
        String encrypted = EncryptionManager.encrypt("", PASSWORD);

        assertEquals("", EncryptionManager.decrypt(encrypted, PASSWORD));
    }

    @Test
    void bytesRoundTrip() throws Exception {
        byte[] plain = randomBytes(64 * 1024);

        byte[] encrypted = EncryptionManager.encrypt(plain, PASSWORD);

        assertArrayEquals(plain, EncryptionManager.decrypt(encrypted, PASSWORD));
    }

    @Test
    void fileRoundTrip(@TempDir Path dir) throws Exception {
        byte[] plain = randomBytes(200_000);
        Path plainFile = dir.resolve("plain.bin");
        Path cipherFile = dir.resolve("cipher.bin");
        Path decryptedFile = dir.resolve("decrypted.bin");
        Files.write(plainFile, plain);

        EncryptionManager.encryptFile(plainFile, cipherFile, PASSWORD);
        EncryptionManager.decryptFile(cipherFile, decryptedFile, PASSWORD);

        byte[] cipher = Files.readAllBytes(cipherFile);
        assertEquals(SALT + IV + plain.length + TAG, cipher.length);
        assertFalse(Arrays.equals(plain, Arrays.copyOfRange(cipher, SALT + IV, SALT + IV + plain.length)));
        assertArrayEquals(plain, Files.readAllBytes(decryptedFile));
    }

    @Test
    void tamperedFileIsRejectedAndNothingIsWritten(@TempDir Path dir) throws Exception {
        Path plainFile = dir.resolve("plain.bin");
        Path cipherFile = dir.resolve("cipher.bin");
        Path decryptedFile = dir.resolve("decrypted.bin");
        Files.write(plainFile, randomBytes(1024));
        EncryptionManager.encryptFile(plainFile, cipherFile, PASSWORD);
        byte[] cipher = Files.readAllBytes(cipherFile);
        cipher[SALT + IV + 10] ^= 0x01;
        Files.write(cipherFile, cipher);

        assertThrows(AEADBadTagException.class,
                () -> EncryptionManager.decryptFile(cipherFile, decryptedFile, PASSWORD));
        assertFalse(Files.exists(decryptedFile));
    }

    @Test
    void outputIsSaltThenIvThenCiphertextWithTag() throws Exception {
        byte[] plain = "sixteen byte msg".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = EncryptionManager.encrypt(plain, PASSWORD);

        assertEquals(SALT + IV + plain.length + TAG, encrypted.length);
    }

    @Test
    void everyMessageGetsAFreshSaltAndIv() throws Exception {
        byte[] plain = "same input".getBytes(StandardCharsets.UTF_8);

        byte[] first = EncryptionManager.encrypt(plain, PASSWORD);
        byte[] second = EncryptionManager.encrypt(plain, PASSWORD);

        assertFalse(Arrays.equals(Arrays.copyOfRange(first, 0, SALT), Arrays.copyOfRange(second, 0, SALT)));
        assertFalse(Arrays.equals(Arrays.copyOfRange(first, SALT, SALT + IV), Arrays.copyOfRange(second, SALT, SALT + IV)));
        assertFalse(Arrays.equals(first, second));
    }

    @Test
    void flippedByteAnywhereFailsTheTagCheck() throws Exception {
        byte[] encrypted = EncryptionManager.encrypt("do not touch".getBytes(StandardCharsets.UTF_8), PASSWORD);
        int[] positions = {
            0,                      // salt
            SALT,                   // iv
            SALT + IV,              // ciphertext
            encrypted.length - 1    // tag
        };

        for (int position : positions) {
            byte[] tampered = encrypted.clone();
            tampered[position] ^= 0x01;

            assertThrows(AEADBadTagException.class,
                    () -> EncryptionManager.decrypt(tampered, PASSWORD),
                    "flipped byte at " + position);
        }
    }

    @Test
    void flippedByteInBase64StringFailsTheTagCheck() throws Exception {
        byte[] raw = Base64.getDecoder().decode(EncryptionManager.encrypt("do not touch", PASSWORD));
        raw[SALT + IV] ^= 0x01;
        String tampered = Base64.getEncoder().encodeToString(raw);

        assertThrows(AEADBadTagException.class, () -> EncryptionManager.decrypt(tampered, PASSWORD));
    }

    @Test
    void wrongPasswordFailsTheTagCheck() throws Exception {
        String encrypted = EncryptionManager.encrypt("secret", PASSWORD);

        assertThrows(AEADBadTagException.class, () -> EncryptionManager.decrypt(encrypted, "not the password"));
    }

    @Test
    void inputShorterThanSaltIvAndTagIsRejected() {
        byte[] tooShort = new byte[SALT + IV + TAG - 1];

        assertThrows(IllegalArgumentException.class, () -> EncryptionManager.decrypt(tooShort, PASSWORD));
    }

    /**
     * Vector produced outside this code base, with Python's hashlib and the
     * "cryptography" package:
     *
     * <pre>
     * salt = bytes(range(16)); iv = bytes(range(100, 112))
     * key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000, dklen=32)
     * ct = AESGCM(key).encrypt(iv, "known answer: ğüşiöç".encode(), None)
     * base64.b64encode(salt + iv + ct)
     * </pre>
     *
     * It pins the key derivation (PBKDF2-HMAC-SHA256, 600 000 iterations,
     * 256-bit key, UTF-8 password), the cipher and the byte layout.
     */
    @Test
    void decryptsVectorFromAnIndependentImplementation() throws Exception {
        String vector = "AAECAwQFBgcICQoLDA0OD2RlZmdoaWprbG1ub+GO4PXSK5kL8q54l0kzeEcHKnAaZP+CiVdJjNGts9Hnm47qnxONj0ai";

        assertEquals("known answer: ğüşiöç", EncryptionManager.decrypt(vector, PASSWORD));
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
}
