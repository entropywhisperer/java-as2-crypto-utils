package io.datachemistry.as2.crypto;

import io.datachemistry.as2.AS2TestUtil;
import io.datachemistry.as2.config.EncryptionAlgorithm;
import io.datachemistry.as2.config.EncryptionConfig;
import io.datachemistry.as2.config.SignatureAlgorithm;
import io.datachemistry.as2.model.AS2Constant;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author entropywhisperer
 */
class AS2EncryptorTest {

    private static final String PUBLIC_CERT = "publiccerts/sender_public.pem";
    private static final String PRIVATE_KEY = "privatekeys/sender_private.pem";
    private static final String RECEIVER_PUBLIC_CERT = "publiccerts/receiver_public.pem";

    private static final String KEY_PASSPHRASE = "pass123";
    private static final String TEST_PAYLOAD = "<move>Foo</move>";

    private AS2Encryptor as2Encryptor;

    @BeforeEach
    void setUp() {
        // Register Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());

        var encryptorConfiguration = EncryptionConfig.builder()
                .privateKey(AS2TestUtil.getBase64PemContent(getClass(), PRIVATE_KEY))
                .privateKeyPassphrase(KEY_PASSPHRASE.toCharArray())
                .publicCert(AS2TestUtil.getBase64PemContent(getClass(), PUBLIC_CERT))
                .receiverPublicCert(AS2TestUtil.getBase64PemContent(getClass(), RECEIVER_PUBLIC_CERT))
                .build();

        this.as2Encryptor = new AS2Encryptor(encryptorConfiguration);
    }

    @Test
    void signAndEncryptMessage_ValidInputs_ValidEnvelopedData() throws CMSException {
        var encryptedMessage = this.as2Encryptor.signAndEncryptMessage(
                TEST_PAYLOAD.getBytes(),
                SignatureAlgorithm.SHA256_WITH_RSA,
                EncryptionAlgorithm.AES256_CBC,
                AS2Constant.ENCRYPT_CONTENT_TYPE
        );
        var envelopedData = new CMSEnvelopedData(encryptedMessage);

        assertTrue(encryptedMessage.length > 0, "Encrypted output should not be empty");

        assertEquals(EncryptionAlgorithm.AES256_CBC.getAlgorithmOid().getId(), envelopedData.getEncryptionAlgOID());
        assertNotEquals(0, envelopedData.getRecipientInfos().size(), "Recipient info should be present");

        assertFalse(
                Arrays.equals(TEST_PAYLOAD.getBytes(), encryptedMessage),
                "Encrypted output should differ from plaintext"
        );
    }

    @Test
    void signAndEncryptMessage_EmptyPayload_ThrowsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> this.as2Encryptor.signAndEncryptMessage(
                null,
                SignatureAlgorithm.SHA256_WITH_RSA,
                EncryptionAlgorithm.AES256_CBC,
                AS2Constant.ENCRYPT_CONTENT_TYPE
            )
        );
    }

    @Test
    void signAndEncryptMessage_EmptySignatureAlgorithm_ThrowsIllegalArgumentException() {
        var payloadBytes = TEST_PAYLOAD.getBytes();

        assertThrows(IllegalArgumentException.class, () -> this.as2Encryptor.signAndEncryptMessage(
                payloadBytes,
                null,
                EncryptionAlgorithm.AES256_CBC,
                AS2Constant.ENCRYPT_CONTENT_TYPE
            )
        );
    }

    @Test
    void signAndEncryptMessage_EmptyEncryptionAlgorithm_ThrowsIllegalArgumentException() {
        var payloadBytes = TEST_PAYLOAD.getBytes();

        assertThrows(IllegalArgumentException.class, () -> this.as2Encryptor.signAndEncryptMessage(
                        payloadBytes,
                        SignatureAlgorithm.SHA256_WITH_RSA,
                        null,
                        AS2Constant.ENCRYPT_CONTENT_TYPE
                )
        );
    }

    @Test
    void signAndEncryptMessage_EmptyContentType_ThrowsIllegalArgumentException() {
        var payloadBytes = TEST_PAYLOAD.getBytes();

        assertThrows(IllegalArgumentException.class, () -> this.as2Encryptor.signAndEncryptMessage(
                        payloadBytes,
                        SignatureAlgorithm.SHA256_WITH_RSA,
                        EncryptionAlgorithm.AES256_CBC,
                        "  "
                )
        );
    }
}
