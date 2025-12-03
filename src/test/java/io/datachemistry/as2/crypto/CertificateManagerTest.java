package io.datachemistry.as2.crypto;

import io.datachemistry.as2.AS2TestUtil;
import io.datachemistry.as2.config.SignatureAlgorithm;
import io.datachemistry.as2.exception.AS2Exception;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author entropywhisperer
 */
class CertificateManagerTest {
    @BeforeEach
    void setUp() {
        // Register Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void getPublicCertificate_ValidCert_X509Initialized() throws AS2Exception {
        var pemContent = AS2TestUtil.getPemContent(getClass(), "publiccerts/sender_public.pem");

        var publicCert = CertificateManager.getPublicCertificate(pemContent);

        assertNotNull(publicCert, "Public cert should not be null");
        assertEquals(SignatureAlgorithm.SHA256_WITH_RSA.getJcaName(), publicCert.getSigAlgName());
    }

    @Test
    void getPublicCertificate_InvalidCert_ThrowsAS2Exception() {
        var pemContent = AS2TestUtil.getPemContent(getClass(), "privatekeys/sender_private.pem");

        var exception = assertThrows(AS2Exception.class, () -> CertificateManager.getPublicCertificate(pemContent));

        assertEquals("Sender certificate is invalid!", exception.getMessage());
    }
}
