package com.secure.snap;

import javax.crypto.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;

public class AllSecureSnap implements GenericSecureSnap {
    private final SecretKey key;
    private final String keyFilePath = "DESClave.ser";
    private String algorithm;
    private String mode;
    private String padding;
    private int keySize;

    public String getAlgorithm() {
        return algorithm + this.keySize + "/" + mode + "/" + padding;
    }


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

    private void saveSecretKey() throws IOException {
        try (ObjectOutputStream fileKey = new ObjectOutputStream(new FileOutputStream(keyFilePath))) {
            fileKey.writeObject(key);
        }
    }

    private SecretKey loadSecretKey() throws IOException, ClassNotFoundException {
        try (ObjectInputStream fileKey = new ObjectInputStream(new FileInputStream(keyFilePath))) {
            return (SecretKey) fileKey.readObject();
        }
    }

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

    public static void main(String[] args) {
        String path = "resources/";
        try {
            AllSecureSnap allSecureSnap = new AllSecureSnap("DESede", "ECB", "PKCS5Padding", 168);
            allSecureSnap.encrypt(path + "image.png", path + "archivocifrado.png");
            System.out.println("File encrypted successfully.");

            allSecureSnap.decrypt(path + "archivocifrado.png", path + "archivosalida.png");
            System.out.println("File decrypted successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

