package com.secure.snap;

import java.math.BigInteger;
import java.security.SecureRandom;

public class ShamirSecretSharing {

    private static final int PRIME_BIT_LENGTH = 512;
    private static final int MINIMUM_SHARES = 3;

    public static void main(String[] args) {
        // Obtener la clave secreta como entrada
        String secretKey = "miClaveSecreta";

        // Compartir la clave secreta entre participantes
        BigInteger[] shares = generateShares(secretKey.getBytes(), MINIMUM_SHARES, MINIMUM_SHARES);

        // Simular la pérdida de algunas acciones
        System.out.println("Acciones generadas:");
        printShares(shares);

        // Reconstruir la clave secreta utilizando el número mínimo de acciones requeridas
        byte[] reconstructedKey = reconstructSecret(shares, MINIMUM_SHARES);

        System.out.println("Clave secreta reconstruida: " + new String(reconstructedKey));
    }

    private static BigInteger[] generateShares(byte[] secret, int totalShares, int threshold) {
        SecureRandom random = new SecureRandom();
        BigInteger prime = BigInteger.probablePrime(PRIME_BIT_LENGTH, random);

        BigInteger[] coefficients = new BigInteger[threshold - 1];
        for (int i = 0; i < threshold - 1; i++) {
            coefficients[i] = new BigInteger(PRIME_BIT_LENGTH, random).mod(prime);
        }

        BigInteger[] shares = new BigInteger[totalShares];
        for (int i = 1; i <= totalShares; i++) {
            BigInteger x = BigInteger.valueOf(i);
            BigInteger share = new BigInteger(secret);

            for (int j = 0; j < threshold - 1; j++) {
                BigInteger term = coefficients[j].multiply(x.pow(j + 1)).mod(prime);
                share = share.add(term).mod(prime);
            }

            shares[i - 1] = share;
        }

        return shares;
    }

    private static byte[] reconstructSecret(BigInteger[] shares, int threshold) {
        BigInteger prime = BigInteger.probablePrime(PRIME_BIT_LENGTH, new SecureRandom());

        byte[] reconstructedSecret = new byte[shares[0].toByteArray().length];
        for (int i = 0; i < threshold; i++) {
            BigInteger xi = BigInteger.valueOf(i + 1);
            BigInteger yi = shares[i];

            BigInteger numerator = BigInteger.ONE;
            BigInteger denominator = BigInteger.ONE;

            for (int j = 0; j < threshold; j++) {
                if (j != i) {
                    BigInteger xj = BigInteger.valueOf(j + 1);

                    numerator = numerator.multiply(BigInteger.ZERO.subtract(xj)).mod(prime);
                    denominator = denominator.multiply(xi.subtract(xj)).mod(prime);
                }
            }

            BigInteger term = yi.multiply(numerator).multiply(denominator.modInverse(prime)).mod(prime);
            byte[] termBytes = term.toByteArray();
            for (int k = 0; k < termBytes.length; k++) {
                reconstructedSecret[k] ^= termBytes[k];
            }
        }

        return reconstructedSecret;
    }

    private static void printShares(BigInteger[] shares) {
        for (int i = 0; i < shares.length; i++) {
            System.out.println("Acción " + (i + 1) + ": " + shares[i]);
        }
    }
}
