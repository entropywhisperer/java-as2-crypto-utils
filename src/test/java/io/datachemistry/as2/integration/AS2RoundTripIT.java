package io.datachemistry.as2.integration;

import io.datachemistry.as2.AS2TestUtil;
import io.datachemistry.as2.config.DecryptionConfig;
import io.datachemistry.as2.config.EncryptionAlgorithm;
import io.datachemistry.as2.config.EncryptionConfig;
import io.datachemistry.as2.config.SignatureAlgorithm;
import io.datachemistry.as2.crypto.AS2Decryptor;
import io.datachemistry.as2.crypto.AS2Encryptor;
import io.datachemistry.as2.exception.AS2Exception;
import io.datachemistry.as2.model.AS2Constant;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author entropywhisperer
 */
class AS2RoundTripIT {
    private static final String SENDER_PUBLIC_CERT = "publiccerts/sender_public.pem";
    private static final String SENDER_PRIVATE_KEY = "privatekeys/sender_private.pem";
    private static final String RECEIVER_PUBLIC_CERT = "publiccerts/receiver_public.pem";
    private static final String RECEIVER_PRIVATE_KEY = "privatekeys/receiver_private.pem";

    private static final String KEY_PASSPHRASE = "pass123";
    private static final String TEST_PAYLOAD = "<employee>John Doe</employee>";

    private AS2Encryptor as2Encryptor;

    @BeforeEach
    void setUp() {
        // Register Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());

        var encryptorConfiguration = EncryptionConfig.builder()
                .privateKey(AS2TestUtil.getBase64PemContent(getClass(), SENDER_PRIVATE_KEY))
                .privateKeyPassphrase(KEY_PASSPHRASE.toCharArray())
                .publicCert(AS2TestUtil.getBase64PemContent(getClass(), SENDER_PUBLIC_CERT))
                .receiverPublicCert(AS2TestUtil.getBase64PemContent(getClass(), RECEIVER_PUBLIC_CERT))
                .build();

        this.as2Encryptor = new AS2Encryptor(encryptorConfiguration);
    }

    @Test
    void signAndEncryptMessage_SignAndEncrypt_ProperlyDecryptAndVerify() {
        var encryptedMessage = this.as2Encryptor.signAndEncryptMessage(
                TEST_PAYLOAD.getBytes(),
                SignatureAlgorithm.SHA256_WITH_RSA,
                EncryptionAlgorithm.AES256_CBC,
                AS2Constant.ENCRYPT_CONTENT_TYPE
        );

        var decryptionConfiguration = DecryptionConfig.builder()
                .privateKey(AS2TestUtil.getBase64PemContent(getClass(), RECEIVER_PRIVATE_KEY))
                .privateKeyPassphrase(KEY_PASSPHRASE.toCharArray())
                .senderPublicCert(AS2TestUtil.getBase64PemContent(getClass(), SENDER_PUBLIC_CERT))
                .build();

        var as2Decryptor = new AS2Decryptor(decryptionConfiguration);

        var result = as2Decryptor.decryptAndVerifyMessage(encryptedMessage, AS2Constant.DECRYPT_CONTENT_TYPE);

        assertEquals(TEST_PAYLOAD, new String(result));
    }

    @Test
    void signAndEncryptMessage_SignAndEncrypt_InvalidDecryptionKey() {
        var encryptedMessage = this.as2Encryptor.signAndEncryptMessage(
                TEST_PAYLOAD.getBytes(),
                SignatureAlgorithm.SHA256_WITH_RSA,
                EncryptionAlgorithm.AES256_CBC,
                AS2Constant.ENCRYPT_CONTENT_TYPE
        );

        var decryptionConfiguration = DecryptionConfig.builder()
                .privateKey(AS2TestUtil.getBase64PemContent(getClass(), SENDER_PRIVATE_KEY)) // Invalid private key
                .privateKeyPassphrase(KEY_PASSPHRASE.toCharArray())
                .senderPublicCert(AS2TestUtil.getBase64PemContent(getClass(), SENDER_PUBLIC_CERT))
                .build();

        var as2Decryptor = new AS2Decryptor(decryptionConfiguration);

        var exception = assertThrows(AS2Exception.class, () -> as2Decryptor.decryptAndVerifyMessage(
                encryptedMessage, AS2Constant.DECRYPT_CONTENT_TYPE));

        assertEquals("Content decryption failed!", exception.getMessage());
    }
}
