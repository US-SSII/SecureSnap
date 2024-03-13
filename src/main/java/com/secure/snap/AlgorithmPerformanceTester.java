package com.secure.snap;

import net.steppschuh.markdowngenerator.table.Table;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AlgorithmPerformanceTester {

    public static void main(String[] args) {
        List<GenericSecureSnap> secureSnaps = new ArrayList<>();
        try {
            secureSnaps.add(new SecureSnap()); // AES con GCM y 256 bits
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
        filesToProcess.add("resources/image7.mp4");
        filesToProcess.add("resources/image8.gif");

        Map<GenericSecureSnap, Long> avgEncryptionTimes = new HashMap<>();
        Map<GenericSecureSnap, Long> avgDecryptionTimes = new HashMap<>();

        for (GenericSecureSnap snap : secureSnaps) {
            try {
                long totalEncryptionTime = testEncryptionTime(snap, filesToProcess);
                long totalDecryptionTime = testDecryptionTime(snap, filesToProcess);
                long avgEncryptionTime = totalEncryptionTime / filesToProcess.size();
                long avgDecryptionTime = totalDecryptionTime / filesToProcess.size();
                avgEncryptionTimes.put(snap, avgEncryptionTime);
                avgDecryptionTimes.put(snap, avgDecryptionTime);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        // Output algorithm performances
        Table.Builder table = new Table.Builder().withAlignments(Table.ALIGN_LEFT, Table.ALIGN_LEFT, Table.ALIGN_LEFT)
                .addRow("Algorithm", "Average Encryption time (milliseconds)", "Average Decryption time (milliseconds)");
        for (GenericSecureSnap snap : secureSnaps) {
            table.addRow(snap.getAlgorithm(), avgEncryptionTimes.get(snap).toString(), avgDecryptionTimes.get(snap).toString());
        }
        System.out.println(table.build());
    }

    public static long testEncryptionTime(GenericSecureSnap snap, List<String> files) throws Exception {
        long totalEncryptionTime = 0;
        for (String file : files) {
            long startTime = System.currentTimeMillis();
            snap.encrypt(file, file + ".enc");
            long endTime = System.currentTimeMillis();
            totalEncryptionTime += (endTime - startTime);
        }
        return totalEncryptionTime;
    }

    public static long testDecryptionTime(GenericSecureSnap snap, List<String> files) throws Exception {
        long totalDecryptionTime = 0;
        for (String file : files) {
            long startTime = System.currentTimeMillis();
            String extension = file.substring(file.lastIndexOf('.'));
            snap.decrypt(file + ".enc", file.replace(extension, "_decrypted" + extension));
            long endTime = System.currentTimeMillis();
            totalDecryptionTime += (endTime - startTime);
        }
        return totalDecryptionTime;
    }
}




