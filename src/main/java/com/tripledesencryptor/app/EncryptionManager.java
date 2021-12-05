package com.tripledesencryptor.app;

import java.security.MessageDigest;
import java.security.Security;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Hamit
 */
public class EncryptionManager {

    /**
     *
     */
    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     *
     * @param message
     * @param pass
     * @return
     * @throws Exception
     */
    public static String encrypt(String message, String pass) throws Exception {
        byte[] input = message.getBytes("IBM1026");
        Encoder encoder = java.util.Base64.getEncoder();
        byte[] encode = encoder.encode(encrypt(input, pass));
        return new String(encode);
    }

    /**
     *
     * @param input
     * @param pass
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(byte[] input, String pass) throws Exception {
        byte[] bytesOfpass = pass.getBytes("IBM1026");
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] keyBytes = md.digest(bytesOfpass);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES/ECB/PKCS7");
        Cipher nCipher = Cipher.getInstance("DeSeDe");
        nCipher.init(Cipher.ENCRYPT_MODE, key);
        return nCipher.doFinal(input);
    }

    /**
     *
     * @param input
     * @param pass
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(byte[] input, String pass) throws Exception {
        byte[] bytesOfpass = pass.getBytes("IBM1026");
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] keyBytes = md.digest(bytesOfpass);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES/ECB/PKCS7");
        Cipher nCipher = Cipher.getInstance("DeSeDe");
        nCipher.init(Cipher.DECRYPT_MODE, key);
        return nCipher.doFinal(input);
    }

    /**
     * Decrypts given string with password
     *
     * @param message string to decrypt
     * @param pass password to decrypt
     * @return decrypted string
     * @throws Exception any kind of exception may be thrown
     */
    public static String decrypt(String message, String pass) throws Exception {
        Decoder decoder = java.util.Base64.getDecoder();
        byte[] decode = decoder.decode(message);
        return new String(decrypt(decode, pass), "IBM1026");
    }
}