package com.smishing;


public class EncryptionModule {
    private String encryptionKey;
    private String algorithmType;

    public EncryptionModule(String key, String algo) {
        this.encryptionKey = key;
        this.algorithmType = algo;
    }

    public String encrypt(String plainText) {
        StringBuilder result = new StringBuilder();
        int shift = encryptionKey.length() % 26;
        for (char c : plainText.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isUpperCase(c) ? 'A' : 'a';
                c = (char) ((c - base + shift) % 26 + base);
            }
            result.append(c);
        }
        return result.toString();
    }

    public String decrypt(String cipherText) {
        StringBuilder result = new StringBuilder();
        int shift = encryptionKey.length() % 26;
        for (char c : cipherText.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isUpperCase(c) ? 'A' : 'a';
                c = (char) ((c - base - shift + 26) % 26 + base);
            }
            result.append(c);
        }
        return result.toString();
    }
} 
