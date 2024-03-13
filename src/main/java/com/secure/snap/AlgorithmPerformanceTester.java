package com.secure.snap;

import net.steppschuh.markdowngenerator.table.Table;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class tests the performance of various encryption algorithms.
 */
public class AlgorithmPerformanceTester {

    /**
     * Main method to run the algorithm performance tests.
     * @param args Command-line arguments (not used)
     */
    public static void main(String[] args) {
        List<GenericSecureSnap> secureSnaps = new ArrayList<>();
        try {
            secureSnaps.add(new SecureSnap()); // AES with GCM and 256 bits
            secureSnaps.add(new AllSecureSnap("Blowfish", "ECB", "PKCS5Padding", 128)); // Blowfish
            secureSnaps.add(new AllSecureSnap("SEED", "ECB", "PKCS5Padding", 128)); // SEED
            secureSnaps.add(new AllSecureSnap("DESede", "ECB", "PKCS5Padding", 168)); // Triple DES
            secureSnaps.add(new AllSecureSnap("Camellia", "ECB", "PKCS5Padding", 128)); // Camellia
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        List<String> filesToProcess = new ArrayList<>();
        filesToProcess.add("resources/image1.jpg");
        filesToProcess.add("resources/image2.jpg");
        filesToProcess.add("resources/image3.zip");
        filesToProcess.add("resources/image4.jpg");
        filesToProcess.add("resources/image5.jpg");
        filesToProcess.add("resources/image6.jpg");
        filesToProcess.add("resources/image7.pdf");
        filesToProcess.add("resources/image8.gif");

        Map<GenericSecureSnap, Long> avgEncryptionTimes = new HashMap<>();
        Map<GenericSecureSnap, Long> avgDecryptionTimes = new HashMap<>();

        for (GenericSecureSnap snap : secureSnaps) {
            try {
                long avgEncryptionTime = testEncryptionTime(snap, filesToProcess);
                long avgDecryptionTime = testDecryptionTime(snap, filesToProcess);
                avgEncryptionTimes.put(snap, avgEncryptionTime);
                avgDecryptionTimes.put(snap, avgDecryptionTime);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        // Output algorithm performances
        printAlgorithmPerformance(secureSnaps, avgEncryptionTimes, avgDecryptionTimes);
    }

    /**
     * Tests the encryption time for a given encryption algorithm.
     * @param snap The encryption algorithm to test
     * @param files The list of files to encrypt
     * @return The average encryption time in milliseconds
     * @throws Exception If an error occurs during encryption
     */
    public static long testEncryptionTime(GenericSecureSnap snap, List<String> files) throws Exception {
        long totalEncryptionTime = 0;
        for (String file : files) {
            totalEncryptionTime += measureEncryptionTime(snap, file);
        }
        return totalEncryptionTime / files.size();
    }

    /**
     * Measures the encryption time for a single file.
     * @param snap The encryption algorithm to use
     * @param file The file to encrypt
     * @return The encryption time in milliseconds
     * @throws Exception If an error occurs during encryption
     */
    public static long measureEncryptionTime(GenericSecureSnap snap, String file) throws Exception {
        long startTime = System.currentTimeMillis();
        snap.encrypt(file, file + ".enc");
        long endTime = System.currentTimeMillis();
        return endTime - startTime;
    }

    /**
     * Tests the decryption time for a given encryption algorithm.
     * @param snap The encryption algorithm to test
     * @param files The list of files to decrypt
     * @return The average decryption time in milliseconds
     * @throws Exception If an error occurs during decryption
     */
    public static long testDecryptionTime(GenericSecureSnap snap, List<String> files) throws Exception {
        long totalDecryptionTime = 0;
        for (String file : files) {
            totalDecryptionTime += measureDecryptionTime(snap, file);
        }
        return totalDecryptionTime / files.size();
    }

    /**
     * Measures the decryption time for a single file.
     * @param snap The encryption algorithm to use
     * @param file The file to decrypt
     * @return The decryption time in milliseconds
     * @throws Exception If an error occurs during decryption
     */
    public static long measureDecryptionTime(GenericSecureSnap snap, String file) throws Exception {
        String extension = file.substring(file.lastIndexOf('.'));
        long startTime = System.currentTimeMillis();
        snap.decrypt(file + ".enc", file.replace(extension, "_decrypted" + snap.getAlgorithm().replace("/", "_") + extension));
        long endTime = System.currentTimeMillis();
        return endTime - startTime;
    }

    /**
     * Prints the algorithm performance in a tabular format.
     * @param secureSnaps The list of encryption algorithms
     * @param avgEncryptionTimes The average encryption times
     * @param avgDecryptionTimes The average decryption times
     */
    public static void printAlgorithmPerformance(List<GenericSecureSnap> secureSnaps,
                                                 Map<GenericSecureSnap, Long> avgEncryptionTimes,
                                                 Map<GenericSecureSnap, Long> avgDecryptionTimes) {
        Table.Builder table = new Table.Builder()
                .withAlignments(Table.ALIGN_LEFT, Table.ALIGN_LEFT, Table.ALIGN_LEFT)
                .addRow("Algorithm", "Average Encryption time (milliseconds)", "Average Decryption time (milliseconds)");
        for (GenericSecureSnap snap : secureSnaps) {
            table.addRow(snap.getAlgorithm(), avgEncryptionTimes.get(snap).toString(), avgDecryptionTimes.get(snap).toString());
        }
        System.out.println(table.build());
    }
}






