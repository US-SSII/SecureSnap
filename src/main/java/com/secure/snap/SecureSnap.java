package com.secure.snap;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Class main.java.SecureSnap for encrypting and decrypting files using AES and GCM.
 */
public class SecureSnap {
    private final SecretKey key;
    private final String keyFilePath = "keyfile.ser";
    private byte[] iv = new byte[12];

    /**
     * Constructor for the main.java.SecureSnap class.
     *
     * @throws Exception If there is an issue initializing the object.
     */
    public SecureSnap() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Try to load the secret key from the file if it exists
        if (Files.exists(Path.of(keyFilePath))) {
            this.key = loadSecretKey();
        } else {
            // Generate the secret key if the file doesn't exist
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // 256-bit key size for AES
            this.key = keyGen.generateKey();

            // Save the secret key to a file
            saveSecretKey();
        }
    }

    /**
     * Saves the secret key to a file.
     *
     * @throws IOException If there is an issue writing to the file.
     */
    private void saveSecretKey() throws IOException {
        try (ObjectOutputStream fileKey = new ObjectOutputStream(new FileOutputStream(keyFilePath))) {
            fileKey.writeObject(key);
        }
    }

    /**
     * Loads the secret key from a file.
     *
     * @return The secret key loaded from the file.
     * @throws IOException            If there is an issue reading from the file.
     * @throws ClassNotFoundException If the class of the key is not found.
     */
    private SecretKey loadSecretKey() throws IOException, ClassNotFoundException {
        try (ObjectInputStream fileKey = new ObjectInputStream(new FileInputStream(keyFilePath))) {
            return (SecretKey) fileKey.readObject();
        }
    }

    /**
     * Encrypts a file using AES and GCM.
     *
     * @param inputFile  Path of the input file.
     * @param outputFile Path of the encrypted output file.
     * @throws Exception If there is an issue during encryption.
     */
    public void encrypt(String inputFile, String outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");

        // Generate a random IV (Initialization Vector)
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // Save the IV to the encrypted file
        try (FileOutputStream ivFile = new FileOutputStream(outputFile + ".iv")) {
            ivFile.write(iv);
        }

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile);
             CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {

            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, bytesRead);
            }
        }
    }

    /**
     * Decrypts an encrypted file using AES and GCM.
     *
     * @param inputFile  Path of the encrypted input file.
     * @param outputFile Path of the decrypted output file.
     * @throws Exception If there is an issue during decryption.
     */
    public void decrypt(String inputFile, String outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");

        // Read the IV from the encrypted file
        try (FileInputStream ivFile = new FileInputStream(inputFile + ".iv")) {
            ivFile.read(iv);
        }

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

        try (FileInputStream fis = new FileInputStream(inputFile);
             CipherInputStream cis = new CipherInputStream(fis, cipher);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = cis.read(buffer)) != -1) {
                fos.write(buffer, 0, bytesRead);
            }
        }
    }

    /**
     * Main method for encrypting and decrypting a sample file.
     *
     * @param args Command-line arguments (not used).
     */
    public static void main(String[] args) {
        String path = "resources/";
        try {
            SecureSnap secureSnap = new SecureSnap();
            secureSnap.encrypt(path + "image.png", path + "imageCyphered.enc");
            System.out.println("File encrypted successfully.");

            secureSnap.decrypt(path + "imageCyphered.enc", path + "imageDecyphered.png");
            System.out.println("File decrypted successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}






