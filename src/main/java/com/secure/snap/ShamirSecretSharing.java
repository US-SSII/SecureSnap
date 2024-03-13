package com.secure.snap;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Implementation of Shamir Secret Sharing algorithm to split and reconstruct a secret key.
 */
public class ShamirSecretSharing {

    private static final int PRIME_BIT_LENGTH = 512;
    private static final int MINIMUM_SHARES = 3;
    private static final BigInteger PRIME = BigInteger.probablePrime(PRIME_BIT_LENGTH, new SecureRandom());

    /**
     * Main method to test splitting and reconstructing the secret key.
     * @param args Command line arguments (not used).
     */
    public static void main(String[] args) {
        String secretKey = "mySecretKey";
        System.out.println( "Secret key:"+secretKey);
        List<BigInteger> shares = generateShares(secretKey.getBytes(), MINIMUM_SHARES, MINIMUM_SHARES);
        System.out.println("Shares generated:");
        printShares(shares);
        byte[] reconstructedKey = reconstructSecret(shares, shares.size());
        System.out.println("Reconstructed secret key: " + new String(reconstructedKey));

        List<BigInteger> sharesIncomplete = shares.subList(0, 2); // Uncomment to test with missing shares
        byte[] reconstructedKeyIncomplete = reconstructSecret(sharesIncomplete, shares.size()); // Uncomment to test with missing shares
        System.out.println("Reconstructed secret key with missing shares: " + new String(reconstructedKeyIncomplete)); // Uncomment to test with missing shares

        // List<BigInteger> sharesOutOfOrder=shares; // Uncomment to test with out-of-order shares
        // sharesOutOfOrder.sort(Comparator.naturalOrder()); // Uncomment to test with out-of-order shares
        // byte[] reconstructedKeyOutOfOrder = reconstructSecret(sharesOutOfOrder, shares.size()); // Uncomment to test with out-of-order shares
        // System.out.println("Reconstructed secret key with out of order shares: " + new String(reconstructedKeyOutOfOrder)); // Uncomment to test with out-of-order shares

    }

    /**
     * Generates shares (parts) of a secret key to share among participants.
     * @param secret The secret key to share.
     * @param totalShares The total number of shares to generate.
     * @param threshold The minimum number of shares required to reconstruct the secret key.
     * @return List of generated shares.
     */
    private static List<BigInteger> generateShares(byte[] secret, int totalShares, int threshold) {
        SecureRandom random = new SecureRandom();
        BigInteger[] coefficients = new BigInteger[threshold];
        for (int i = 0; i < threshold; i++) {
            coefficients[i] = new BigInteger(PRIME.bitLength(), random).mod(PRIME);
        }

        List<BigInteger> shares = new ArrayList<>();
        for (int i = 1; i <= totalShares; i++) {
            BigInteger x = BigInteger.valueOf(i);
            BigInteger share = new BigInteger(secret);
            for (int j = 1; j < threshold; j++) {
                BigInteger term = coefficients[j].multiply(x.pow(j)).mod(PRIME);
                share = share.add(term).mod(PRIME);
            }
            shares.add(share);
        }
        return shares;
    }

    /**
     * Reconstructs the secret key from the given shares.
     * @param shares List of shares.
     * @param threshold The minimum number of shares required to reconstruct the secret key.
     * @return The reconstructed secret key.
     */
    private static byte[] reconstructSecret(List<BigInteger> shares, int threshold) {
        BigInteger secret = BigInteger.ZERO;
        for (int i = 0; i < threshold; i++) {
            BigInteger xi = BigInteger.valueOf(i + 1);
            BigInteger yi = shares.get(i);

            BigInteger numerator = BigInteger.ONE;
            BigInteger denominator = BigInteger.ONE;

            for (int j = 0; j < threshold; j++) {
                if (j != i) {
                    BigInteger xj = BigInteger.valueOf(j + 1);
                    numerator = numerator.multiply(xj.negate()).mod(PRIME);
                    denominator = denominator.multiply(xi.subtract(xj)).mod(PRIME);
                }
            }

            BigInteger term = yi.multiply(numerator).multiply(denominator.modInverse(PRIME)).mod(PRIME);
            secret = secret.add(term).mod(PRIME);
        }
        return secret.toByteArray();
    }

    /**
     * Prints the generated shares to the console.
     * @param shares List of shares.
     */
    private static void printShares(List<BigInteger> shares) {
        for (int i = 0; i < shares.size(); i++) {
            System.out.println("Share " + (i + 1) + ": " + shares.get(i));
        }
    }
}



