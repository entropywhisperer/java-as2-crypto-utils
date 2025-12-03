package io.datachemistry.as2.crypto;

import io.datachemistry.as2.AS2TestUtil;
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
class KeyManagerTest {
    private static final char[] PASSPHRASE = "pass123".toCharArray();

    @BeforeEach
    void setUp() {
        // Register Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void getPrivateKey_ValidKey_PrivateKeyInitialized() throws AS2Exception {
        var pemContent = AS2TestUtil.getPemContent(getClass(),"privatekeys/sender_private.pem");

        var privateKey = KeyManager.getPrivateKey(pemContent, PASSPHRASE);

        assertNotNull(privateKey, "PrivateKey should not be null");
        assertEquals("RSA", privateKey.getAlgorithm(), "Expected RSA algorithm");
        assertEquals("PKCS#8", privateKey.getFormat(), "Expected PKCS#8 format");
    }

    @Test
    void getPrivateKey_InvalidKey_ThrowsAS2Exception() {
        var pemContent = AS2TestUtil.getPemContent(getClass(),"publiccerts/sender_public.pem");

        var exception = assertThrows(AS2Exception.class, () -> KeyManager.getPrivateKey(pemContent, PASSPHRASE));

        assertEquals("Invalid private key", exception.getMessage());
    }
}
