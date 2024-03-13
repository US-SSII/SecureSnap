package com.secure.snap;

public interface GenericSecureSnap {

    void encrypt(String inputFile, String outputFile) throws Exception;
    void decrypt(String inputFile, String outputFile) throws Exception;

    String getAlgorithm();
}
