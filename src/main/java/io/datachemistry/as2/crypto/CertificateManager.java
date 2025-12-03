package io.datachemistry.as2.crypto;

import io.datachemistry.as2.exception.AS2Exception;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Utility class for managing X.509 certificates.
 *
 * @author entropywhisperer
 */
final class CertificateManager {
    private CertificateManager() {
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * Loads an X.509 public certificate from PEM data.
     *
     * @param publicCert PEM certificate data
     * @return the loaded X.509 certificate
     * @throws AS2Exception if the certificate data is invalid or cannot be parsed
     */
    public static X509Certificate getPublicCertificate(byte[] publicCert) throws AS2Exception {
        try (InputStream inputStream = new ByteArrayInputStream(publicCert)) {
            var certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(inputStream);
        } catch (Exception exception) {
            throw new AS2Exception("Sender certificate is invalid!", exception);
        }
    }
}