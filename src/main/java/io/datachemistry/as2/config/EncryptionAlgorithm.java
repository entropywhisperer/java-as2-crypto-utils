package io.datachemistry.as2.config;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;

/**
 * Supported content encryption algorithms for AS2 (S/MIME).
 * These algorithms are used for encrypting message content in AS2 payloads.
 *
 * @author entropywhisperer
 */
public enum EncryptionAlgorithm {
    /**
     * AES (Advanced Encryption Standard) with 128-bit key in CBC (Cipher Block Chaining) mode.
     * Provides strong security with good performance for most use cases.
     */
    AES128_CBC(CMSAlgorithm.AES128_CBC),

    /**
     * AES with 192-bit key in CBC mode.
     * Provides enhanced security over AES-128 for sensitive data.
     */
    AES192_CBC(CMSAlgorithm.AES192_CBC),

    /**
     * AES with 256-bit key in CBC mode.
     * Provides the highest level of security among AES variants for highly sensitive data.
     * Recommended for applications requiring maximum security.
     */
    AES256_CBC(CMSAlgorithm.AES256_CBC);

    /**
     * ASN.1 object identifier for the encryption algorithm.
     * Used internally by the cryptographic library to identify the algorithm.
     */
    private final ASN1ObjectIdentifier algorithmOid;

    EncryptionAlgorithm(ASN1ObjectIdentifier algorithmOid) {
        this.algorithmOid = algorithmOid;
    }

    public ASN1ObjectIdentifier getAlgorithmOid() {
        return this.algorithmOid;
    }
}
