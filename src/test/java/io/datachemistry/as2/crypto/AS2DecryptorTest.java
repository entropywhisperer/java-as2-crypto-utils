package io.datachemistry.as2.crypto;

import io.datachemistry.as2.AS2TestUtil;
import io.datachemistry.as2.config.DecryptionConfig;
import io.datachemistry.as2.exception.AS2Exception;
import io.datachemistry.as2.model.AS2Constant;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author entropywhisperer
 */
class AS2DecryptorTest {
    private static final String PRIVATE_KEY = "privatekeys/receiver_private.pem";
    private static final String SENDER_PUBLIC_CERT = "publiccerts/sender_public.pem";

    private static final String KEY_PASSPHRASE = "pass123";
    private static final String TEST_PAYLOAD = "<move>Foo</move>";

    @BeforeEach
    void setUp() {
        // Register Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void getEncryptedData_ValidEncryptedMessage_DecryptContent() throws AS2Exception, IOException {
        var decryptionConfiguration = DecryptionConfig.builder()
                .privateKey(AS2TestUtil.getBase64PemContent(getClass(), PRIVATE_KEY))
                .privateKeyPassphrase(KEY_PASSPHRASE.toCharArray())
                .senderPublicCert(AS2TestUtil.getBase64PemContent(getClass(), SENDER_PUBLIC_CERT))
                .build();

        var as2Decryptor = new AS2Decryptor(decryptionConfiguration);

        try (var outputStream = getClass().getClassLoader().getResourceAsStream(
                "messages/encrypted_signed_message.bin")) {
            if (outputStream == null) {
                throw new RuntimeException("Couldn't read encrypted message!");
            }
            var decryptedContent = as2Decryptor.getEncryptedData(
                    outputStream.readAllBytes(), AS2Constant.DECRYPT_CONTENT_TYPE);

            assertNotNull(decryptedContent, "Content should not be null");
            assertEquals(TEST_PAYLOAD, new String(decryptedContent, StandardCharsets.UTF_8));
        }
    }
}
