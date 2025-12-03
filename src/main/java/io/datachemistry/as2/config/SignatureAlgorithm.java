package io.datachemistry.as2.config;

/**
 * Supported digital signature algorithms for AS2 (S/MIME).
 * These algorithms are used for signing AS2 messages to ensure authenticity,
 * integrity, and non-repudiation.
 *
 * @author entropywhisperer
 */
public enum SignatureAlgorithm {
    /**
     * RSA signature with SHA-256 hash algorithm.
     * Provides a good balance of security and performance for most AS2 transactions.
     * Recommended for general business document exchange.
     */
    SHA256_WITH_RSA("SHA256withRSA"),

    /**
     * RSA signature with SHA-384 hash algorithm.
     * Provides enhanced security with a 384-bit hash for sensitive transactions.
     * Suitable for regulated industries or high-value document exchange.
     */
    SHA384_WITH_RSA("SHA384withRSA"),

    /**
     * RSA signature with SHA-512 hash algorithm.
     * Provides the highest level of security with a 512-bit hash.
     * Recommended for highly sensitive data or when maximum security is required.
     */
    SHA512_WITH_RSA("SHA512withRSA");

    /**
     * Standard Java Cryptography Architecture (JCA) algorithm name.
     * This is the format expected by Java security APIs like {@link java.security.Signature}.
     */
    private final String jcaAlgorithmName;

    SignatureAlgorithm(String jcaAlgorithmName) {
        this.jcaAlgorithmName = jcaAlgorithmName;
    }

    public String getJcaName() {
        return jcaAlgorithmName;
    }
}