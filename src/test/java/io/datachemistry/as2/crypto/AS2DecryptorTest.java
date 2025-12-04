package io.datachemistry.as2.crypto;

import io.datachemistry.as2.AS2TestUtil;
import io.datachemistry.as2.config.DecryptionConfig;
import io.datachemistry.as2.model.AS2Constant;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author entropywhisperer
 */
class AS2DecryptorTest {
    private static final String PRIVATE_KEY = "privatekeys/receiver_private.pem";
    private static final String SENDER_PUBLIC_CERT = "publiccerts/sender_public.pem";

    private static final String KEY_PASSPHRASE = "pass123";
    private static final String TEST_PAYLOAD = "<move>Foo</move>";

    private AS2Decryptor as2Decryptor;

    @BeforeEach
    void setUp() {
        // Register Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());

        var decryptionConfiguration = DecryptionConfig.builder()
                .privateKey(AS2TestUtil.getBase64PemContent(getClass(), PRIVATE_KEY))
                .privateKeyPassphrase(KEY_PASSPHRASE.toCharArray())
                .senderPublicCert(AS2TestUtil.getBase64PemContent(getClass(), SENDER_PUBLIC_CERT))
                .build();

        this.as2Decryptor = new AS2Decryptor(decryptionConfiguration);
    }

    @Test
    void decryptAndVerifyMessage_ValidEncryptedMessage_DecryptContent() throws IOException {
        try (var outputStream = getClass().getClassLoader().getResourceAsStream(
                "messages/encrypted_signed_message.bin")) {
            if (outputStream == null) {
                throw new RuntimeException("Couldn't read encrypted message!");
            }
            var decryptedContent = this.as2Decryptor.decryptAndVerifyMessage(
                    outputStream.readAllBytes(), AS2Constant.DECRYPT_CONTENT_TYPE);

            assertNotNull(decryptedContent, "Content should not be null");
            assertEquals(TEST_PAYLOAD, new String(decryptedContent, StandardCharsets.UTF_8));
        }
    }

    @Test
    void decryptAndVerifyMessage_EmptyEncryptedData_ThrowsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> as2Decryptor.decryptAndVerifyMessage(
                null, AS2Constant.DECRYPT_CONTENT_TYPE
        ));
    }

    @Test
    void decryptAndVerifyMessage_EmptyContentType_ThrowsIllegalArgumentException() throws IOException {
        try (var outputStream = getClass().getClassLoader().getResourceAsStream(
                "messages/encrypted_signed_message.bin")) {
            if (outputStream == null) {
                throw new RuntimeException("Couldn't read encrypted message!");
            }

            var encryptedData = outputStream.readAllBytes();

            assertThrows(IllegalArgumentException.class, () -> as2Decryptor.decryptAndVerifyMessage(
                    encryptedData, null
            ));
        }
    }
}
