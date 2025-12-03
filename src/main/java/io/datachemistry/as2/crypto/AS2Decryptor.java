package io.datachemistry.as2.crypto;

import io.datachemistry.as2.config.DecryptionConfig;
import io.datachemistry.as2.exception.AS2Exception;
import io.datachemistry.as2.model.AS2DecryptedMessage;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;
import javax.mail.util.SharedByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Handles AS2 message decryption and signature verification.
 *
 * @author entropywhisperer
 */
public class AS2Decryptor {
    private static final String BOUNCY_CASTLE_PROVIDER = "BC";
    private static final Logger logger = LoggerFactory.getLogger(AS2Decryptor.class);

    private final X509Certificate senderPublicCert;
    private final PrivateKey privateKey;

    /**
     * Constructs a decryptor with the provided configuration.
     *
     * @param configuration the decryption configuration containing certificates and keys
     * @throws AS2Exception if certificate or key loading fails
     */
    public AS2Decryptor(DecryptionConfig configuration) throws AS2Exception {
        try (configuration) {
            this.senderPublicCert = CertificateManager.getPublicCertificate(
                    Base64.getDecoder().decode(configuration.getSenderPublicCert())
            );

            this.privateKey = KeyManager.getPrivateKey(
                    Base64.getDecoder().decode(configuration.getPrivateKey()),
                    configuration.getPrivateKeyPassphrase()
            );
        }
    }

    /**
     * Decrypts data and verifies its signature.
     *
     * @param encryptedData        the encrypted data bytes
     * @param decryptedContentType the expected content type after decryption
     * @return the verified and decrypted content as UTF-8 bytes
     * @throws AS2Exception if decryption or signature verification fails
     */
    public byte[] getEncryptedData(byte[] encryptedData, String decryptedContentType) throws AS2Exception {
        var decryptedContent = getDecryptedContent(encryptedData);
        var multipart = getSignedMimeMultipart(decryptedContent, decryptedContentType);
        var payload = getFullPayload(multipart);
        var isSignatureValid = isSignatureValid(multipart, payload.fullPayload());

        if (!isSignatureValid) {
            throw new AS2Exception("Invalid signature!");
        }

        return payload.content().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Decrypts content using the private key.
     *
     * @param encryptedData the encrypted data bytes
     * @return the decrypted content bytes
     * @throws AS2Exception if decryption fails
     */
    private byte[] getDecryptedContent(byte[] encryptedData) throws AS2Exception {
        try {
            logger.debug("Decrypting content with Private Key");

            var envelopedData = new CMSEnvelopedData(encryptedData);
            var recipientInformation = envelopedData.getRecipientInfos().getRecipients().iterator().next();

            return recipientInformation.getContent(
                    new JceKeyTransEnvelopedRecipient(this.privateKey).setProvider(BOUNCY_CASTLE_PROVIDER));
        } catch (CMSException exception) {
            throw new AS2Exception("Content decryption failed!", exception);
        }
    }

    /**
     * Parses decrypted content into a MIME multipart structure.
     *
     * @param decryptedContent     the decrypted content bytes
     * @param decryptedContentType the content type for parsing
     * @return the parsed MIME multipart structure
     * @throws AS2Exception if parsing fails
     */
    private MimeMultipart getSignedMimeMultipart(
            byte[] decryptedContent, String decryptedContentType) throws AS2Exception {
        try {
            var dataSource = new ByteArrayDataSource(decryptedContent, decryptedContentType);
            return new MimeMultipart(dataSource);
        } catch (MessagingException exception) {
            throw new AS2Exception("MIME Multipart parse error!", exception);
        }
    }

    /**
     * Extracts the full payload from a MIME multipart message.
     *
     * @param multipart the MIME multipart containing the payload
     * @return the decrypted message with both raw bytes and string content
     * @throws AS2Exception if payload extraction fails
     */
    private AS2DecryptedMessage getFullPayload(MimeMultipart multipart) throws AS2Exception {
        try (var outputStream = new ByteArrayOutputStream()) {
            var payloadPart = (MimeBodyPart) multipart.getBodyPart(0);
            payloadPart.writeTo(outputStream);
            var content = convertToString(payloadPart.getContent());

            return new AS2DecryptedMessage(outputStream.toByteArray(), content);
        } catch (IOException | MessagingException exception) {
            throw new AS2Exception("Invalid payload!", exception);
        }
    }

    /**
     * Converts payload content to a string.
     *
     * @param payloadContent the payload content object
     * @return the content as a string
     * @throws AS2Exception if conversion fails
     */
    private String convertToString(Object payloadContent) throws AS2Exception {
        try {
            if (payloadContent instanceof SharedByteArrayInputStream inputStream) {
                var bytes = new byte[inputStream.available()];

                logger.debug("Bytes read: {}", inputStream.read(bytes));

                return new String(bytes, StandardCharsets.UTF_8);
            }

            return "Invalid content";
        } catch (IOException exception) {
            throw new AS2Exception("Couldn't read the content!", exception);
        }
    }

    /**
     * Verifies the digital signature of a multipart message.
     *
     * @param multipart   the MIME multipart containing the signature
     * @param fullPayload the full payload bytes to verify against
     * @return true if the signature is valid, false otherwise
     * @throws AS2Exception if signature verification process fails
     */
    private boolean isSignatureValid(MimeMultipart multipart, byte[] fullPayload) throws AS2Exception {
        try {
            var signaturePart = (MimeBodyPart) multipart.getBodyPart(1);
            var signatureBytes = signaturePart.getInputStream().readAllBytes();

            var cmsPayload = new CMSProcessableByteArray(fullPayload);
            var signedData = new CMSSignedData(cmsPayload, signatureBytes);

            var verifier = new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider(BOUNCY_CASTLE_PROVIDER).build(this.senderPublicCert);

            var signer = signedData.getSignerInfos().getSigners().iterator().next();
            return signer.verify(verifier);
        } catch (CMSException | OperatorCreationException | MessagingException | IOException exception) {
            throw new AS2Exception("Couldn't verify the signature!", exception);
        }
    }
}