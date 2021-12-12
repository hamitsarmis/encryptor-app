package com.tripledesencryptor.app;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Hello world!
 *
 */
public class App {

    public static void main(String[] args) throws Exception {
        String choice;
        ArrayList<String> availableOptions = new ArrayList<String>();
        availableOptions.add("1");
        availableOptions.add("2");
        availableOptions.add("3");

        while (availableOptions.indexOf((choice = readFromConsole(getUsage()))) != -1) {
            String password = readFromConsole("Pass?");
            if (choice.equals("1")) {
                Boolean encrypt = readFromConsole("1. encrypt or 2. decyrpt ?").equals("1");
                String passToEncrypt = readFromConsole("word?");
                if (encrypt) {
                    String enc = EncryptionManager.encrypt(passToEncrypt, password);
                    System.out.println("Encryption Result: " + enc);
                    System.out.println("Decryption Result: " + EncryptionManager.decrypt(enc, password));
                }
                else {
                    String dec = EncryptionManager.decrypt(passToEncrypt, password);
                    System.out.println("Decryption Result: " + dec);
                    System.out.println("Encryption Result: " + EncryptionManager.encrypt(dec, password));
                }
            } else if (choice.equals("2") || choice.equals("3")) {
                if (choice.equals("2")) {
                    byte[] input = readFile(readFromConsole("Path to read?"));
                    writeToFile(readFromConsole("Path to write?"), EncryptionManager.encrypt(input, password));
                } else if (choice.equals("3")) {
                    byte[] input = readFile(readFromConsole("Path to read?"));
                    writeToFile(readFromConsole("Path to write?"), EncryptionManager.decrypt(input, password));
                }
            }
        }
    }

    /**
     *
     * @param filename
     * @param output
     * @throws IOException
     */
    public static void writeToFile(String filename, byte[] output) throws IOException {
        BufferedOutputStream bos;
        FileOutputStream fos = new FileOutputStream(new File(filename));
        bos = new BufferedOutputStream(fos);
        bos.write(output);
        bos.close();
    }

    /**
     *
     * @param file
     * @return
     * @throws IOException
     */
    public static byte[] readFile(String file) throws IOException {
        return readFile(new File(file));
    }

    /**
     *
     * @param file
     * @return
     * @throws IOException
     */
    public static byte[] readFile(File file) throws IOException {
        // Open file
        RandomAccessFile f = new RandomAccessFile(file, "r");
        try {
            // Get and check length
            long longlength = f.length();
            int length = (int) longlength;
            if (length != longlength) {
                throw new IOException("File size >= 2 GB");
            }
            // Read file and return data
            byte[] data = new byte[length];
            f.readFully(data);
            return data;
        } finally {
            f.close();
        }
    }

    /**
     *
     * @param message
     * @return
     */
    public static String readFromConsole(String message) {
        System.out.println(message);
        BufferedReader br = null;
        try {
            br = new BufferedReader(new InputStreamReader(System.in, "UTF-8"));
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            return br.readLine();

        } catch (IOException ex) {
            Logger.getLogger(App.class
                    .getName()).log(Level.SEVERE, null, ex);
        }
        return "";
    }

    /**
     *
     * @return
     */
    public static String getUsage() {
        return "Usage:\n1. String encryption & decryption\n2. File encryption\n3. File decryption";
    }

}