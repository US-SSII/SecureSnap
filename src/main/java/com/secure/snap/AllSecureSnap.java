package com.secure.snap;

import javax.crypto.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Implementation of GenericSecureSnap for handling encryption and decryption using various algorithms and parameters.
 */
public class AllSecureSnap implements GenericSecureSnap {

    private final SecretKey key;
    private final String keyFilePath = "DESClave.ser";
    private String algorithm;
    private String mode;
    private String padding;
    private int keySize;

    /**
     * Initializes the AllSecureSnap instance with the specified algorithm, mode, padding, and key size.
     *
     * @param algorithm The encryption algorithm to use.
     * @param mode      The encryption mode to use.
     * @param padding   The padding scheme to use.
     * @param keySize   The size of the encryption key.
     * @throws Exception If an error occurs during key generation or loading.
     */
    public AllSecureSnap(String algorithm, String mode, String padding, int keySize) throws Exception {
        this.algorithm = algorithm;
        this.mode = mode;
        this.padding = padding;
        this.keySize = keySize;

        if (Files.exists(Path.of(keyFilePath))) {
            this.key = loadSecretKey();
        } else {
            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            keyGen.init(keySize);
            this.key = keyGen.generateKey();
            saveSecretKey();
        }
    }

    /**
     * Retrieves the algorithm used for encryption and decryption.
     *
     * @return The encryption algorithm with its parameters.
     */
    public String getAlgorithm() {
        return algorithm + this.keySize + "/" + mode + "/" + padding;
    }

    /**
     * Encrypts the input file and saves the encrypted data to the output file.
     *
     * @param inputFile  The path to the input file to be encrypted.
     * @param outputFile The path to save the encrypted output.
     * @throws Exception If an error occurs during encryption.
     */
    public void encrypt(String inputFile, String outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/" + padding);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(inputFile));
             CipherOutputStream cos = new CipherOutputStream(new BufferedOutputStream(new FileOutputStream(outputFile)), cipher)) {

            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = bis.read(buffer)) != -1) {
                cos.write(buffer, 0, bytesRead);
            }
        }
    }

    /**
     * Decrypts the input file and saves the decrypted data to the output file.
     *
     * @param inputFile  The path to the input file to be decrypted.
     * @param outputFile The path to save the decrypted output.
     * @throws Exception If an error occurs during decryption.
     */
    public void decrypt(String inputFile, String outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/" + padding);
        cipher.init(Cipher.DECRYPT_MODE, key);

        try (CipherInputStream cis = new CipherInputStream(new BufferedInputStream(new FileInputStream(inputFile)), cipher);
             BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputFile))) {

            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = cis.read(buffer)) != -1) {
                bos.write(buffer, 0, bytesRead);
            }
        }
    }

    /**
     * Saves the generated secret key to a file.
     *
     * @throws IOException If an error occurs during file I/O.
     */
    private void saveSecretKey() throws IOException {
        try (ObjectOutputStream fileKey = new ObjectOutputStream(new FileOutputStream(keyFilePath))) {
            fileKey.writeObject(key);
        }
    }

    /**
     * Loads the secret key from a file.
     *
     * @return The loaded secret key.
     * @throws IOException            If an error occurs during file I/O.
     * @throws ClassNotFoundException If the class of the serialized object cannot be found.
     */
    private SecretKey loadSecretKey() throws IOException, ClassNotFoundException {
        try (ObjectInputStream fileKey = new ObjectInputStream(new FileInputStream(keyFilePath))) {
            return (SecretKey) fileKey.readObject();
        }
    }
}


