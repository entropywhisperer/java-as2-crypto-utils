package io.datachemistry.as2.config;

import java.util.Arrays;
import java.util.Objects;

/**
 * Configuration class for encrypting AS2 messages.
 * Contains the necessary cryptographic materials for signing and encrypting
 * outgoing AS2 messages secured with S/MIME.
 *
 * @author entropywhisperer
 */
public class EncryptionConfig implements AutoCloseable {
    private final String privateKey;
    private final char[] privateKeyPassphrase;
    private final String publicCert;
    private final String receiverPublicCert;

    /**
     * @param privateKey           The sender's private key for signing the message
     * @param privateKeyPassphrase The passphrase for decrypting the private key
     * @param publicCert           The sender's public certificate for inclusion in the signature
     * @param receiverPublicCert   The recipient's public certificate for encrypting the message
     */
    private EncryptionConfig(
            String privateKey,
            char[] privateKeyPassphrase,
            String publicCert,
            String receiverPublicCert
    ) {
        Objects.requireNonNull(privateKey, "privateKey must not be null");
        Objects.requireNonNull(privateKeyPassphrase, "privateKeyPassphrase must not be null");
        Objects.requireNonNull(publicCert, "publicCert must not be null");
        Objects.requireNonNull(receiverPublicCert, "receiverPublicCert must not be null");

        if (privateKey.isBlank()) {
            throw new IllegalArgumentException("privateKey must not be blank");
        }
        if (privateKeyPassphrase.length == 0) {
            throw new IllegalArgumentException("privateKeyPassphrase must not be blank");
        }
        if (publicCert.isBlank()) {
            throw new IllegalArgumentException("publicCert must not be blank");
        }
        if (receiverPublicCert.isBlank()) {
            throw new IllegalArgumentException("receiverPublicCert must not be blank");
        }

        this.privateKey = privateKey;
        this.privateKeyPassphrase = privateKeyPassphrase;
        this.publicCert = publicCert;
        this.receiverPublicCert = receiverPublicCert;
    }

    public static class Builder {
        private String privateKey;
        private char[] privateKeyPassphrase;
        private String publicCert;
        private String receiverPublicCert;

        private Builder() {
        }

        public static Builder builder() {
            return new Builder();
        }

        public Builder privateKey(String privateKey) {
            this.privateKey = privateKey;
            return this;
        }

        public Builder privateKeyPassphrase(char[] privateKeyPassphrase) {
            this.privateKeyPassphrase = privateKeyPassphrase;
            return this;
        }

        public Builder publicCert(String publicCert) {
            this.publicCert = publicCert;
            return this;
        }

        public Builder receiverPublicCert(String receiverPublicCert) {
            this.receiverPublicCert = receiverPublicCert;
            return this;
        }

        public EncryptionConfig build() {
            return new EncryptionConfig(privateKey, privateKeyPassphrase, publicCert, receiverPublicCert);
        }
    }

    public static Builder builder() {
        return Builder.builder();
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public char[] getPrivateKeyPassphrase() {
        return privateKeyPassphrase.clone();
    }

    public String getPublicCert() {
        return publicCert;
    }

    public String getReceiverPublicCert() {
        return receiverPublicCert;
    }

    public void clearSensitiveData() {
        if (this.privateKeyPassphrase != null) {
            Arrays.fill(this.privateKeyPassphrase, '\0');
        }
    }

    @Override
    public void close() {
        this.clearSensitiveData();
    }
}