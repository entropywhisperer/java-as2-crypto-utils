package io.datachemistry.as2.config;

import java.util.Arrays;
import java.util.Objects;

/**
 * Configuration class for decrypting AS2 messages.
 * Contains the necessary cryptographic materials for decrypting and verifying
 * incoming AS2 messages secured with S/MIME.
 *
 * @author entropywhisperer
 */
public class DecryptionConfig implements AutoCloseable {
    private final String privateKey;
    private final char[] privateKeyPassphrase;
    private final String senderPublicCert;

    /**
     * @param privateKey           The private key in PEM format used for decrypting incoming AS2 messages
     * @param privateKeyPassphrase The passphrase for decrypting the private key
     * @param senderPublicCert     The X.509 public certificate of the sender for signature verification
     */
    private DecryptionConfig(String privateKey,
                             char[] privateKeyPassphrase,
                             String senderPublicCert) {
        Objects.requireNonNull(privateKey, "privateKey must not be null");
        Objects.requireNonNull(privateKeyPassphrase, "privateKeyPassphrase must not be null");
        Objects.requireNonNull(senderPublicCert, "senderPublicCert must not be null");

        if (privateKey.isBlank()) {
            throw new IllegalArgumentException("privateKey must not be blank");
        }
        if (privateKeyPassphrase.length == 0) {
            throw new IllegalArgumentException("privateKeyPassphrase must not be blank");
        }
        if (senderPublicCert.isBlank()) {
            throw new IllegalArgumentException("senderPublicCert must not be blank");
        }

        this.privateKey = privateKey;
        this.privateKeyPassphrase = privateKeyPassphrase;
        this.senderPublicCert = senderPublicCert;
    }

    public static class Builder {
        private String privateKey;
        private char[] privateKeyPassphrase;
        private String senderPublicCert;

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

        public Builder senderPublicCert(String senderPublicCert) {
            this.senderPublicCert = senderPublicCert;
            return this;
        }

        public DecryptionConfig build() {
            return new DecryptionConfig(privateKey, privateKeyPassphrase, senderPublicCert);
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

    public String getSenderPublicCert() {
        return senderPublicCert;
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
