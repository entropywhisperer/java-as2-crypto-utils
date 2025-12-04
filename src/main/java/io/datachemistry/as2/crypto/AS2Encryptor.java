package io.datachemistry.as2.crypto;

import io.datachemistry.as2.config.EncryptionAlgorithm;
import io.datachemistry.as2.config.EncryptionConfig;
import io.datachemistry.as2.config.SignatureAlgorithm;
import io.datachemistry.as2.exception.AS2Exception;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.activation.DataHandler;
import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;

/**
 * Handles AS2 message encryption and signing.
 *
 * @author entropywhisperer
 */
public class AS2Encryptor {
    private static final String BOUNCY_CASTLE_PROVIDER = "BC";
    private static final Logger logger = LoggerFactory.getLogger(AS2Encryptor.class);

    private final X509Certificate receiverPublicCert;
    private final X509Certificate publicCert;
    private final PrivateKey privateKey;

    /**
     * Constructs an encryptor with the provided configuration.
     *
     * @param configuration the encryption configuration containing certificates and keys
     * @throws AS2Exception if certificate or key loading fails
     */
    public AS2Encryptor(EncryptionConfig configuration) {
        try (configuration) {
            this.receiverPublicCert = CertificateManager.getPublicCertificate(
                    Base64.getDecoder().decode(configuration.getReceiverPublicCert())
            );
            this.publicCert = CertificateManager.getPublicCertificate(
                    Base64.getDecoder().decode(configuration.getPublicCert())
            );

            this.privateKey = KeyManager.getPrivateKey(
                    Base64.getDecoder().decode(configuration.getPrivateKey()),
                    configuration.getPrivateKeyPassphrase()
            );
        }
    }

    /**
     * Encrypts and signs a message payload for AS2 transmission.
     *
     * @param payload             the raw message payload to encrypt and sign
     * @param signatureAlgorithm  the algorithm to use for digital signing
     * @param encryptionAlgorithm the algorithm to use for encryption
     * @param contentType         the MIME content type of the payload
     * @return the encrypted and signed data as DER-encoded bytes
     * @throws IllegalArgumentException if any parameter is null or empty
     * @throws AS2Exception if encryption or signing fails
     */
    public byte[] signAndEncryptMessage(
            byte[] payload,
            SignatureAlgorithm signatureAlgorithm,
            EncryptionAlgorithm encryptionAlgorithm,
            String contentType
    ) {
        if (signatureAlgorithm == null) {
            throw new IllegalArgumentException("Signature algorithm cannot be null");
        }

        if (encryptionAlgorithm == null) {
            throw new IllegalArgumentException("Encryption algorithm cannot be null");
        }

        if (contentType == null || contentType.isBlank()) {
            throw new IllegalArgumentException("Content type cannot be empty");
        }

        if (payload == null || payload.length == 0) {
            throw new IllegalArgumentException("Payload cannot be empty");
        }

        var signedPayload = signPayload(
                contentType,
                payload,
                signatureAlgorithm.getJcaName()
        );
        return encryptPayload(
                signedPayload,
                receiverPublicCert,
                encryptionAlgorithm.getAlgorithmOid()
        );
    }

    /**
     * Signs a payload using S/MIME signing.
     *
     * @param contentType  the MIME content type of the payload
     * @param payload      the data to sign
     * @param signatureAlg the signature algorithm to use
     * @return a MIME multipart containing the signed content
     * @throws AS2Exception if signing fails
     */
    private MimeMultipart signPayload(String contentType, byte[] payload, String signatureAlg) {
        try {
            logger.debug("Signing payload using algorithm: {}", signatureAlg);

            var payloadPart = new MimeBodyPart();
            payloadPart.setDataHandler(new DataHandler(new ByteArrayDataSource(
                    payload, contentType)));
            payloadPart.setHeader("Content-Type", contentType);
            payloadPart.setHeader("Content-Transfer-Encoding", "7bit");

            var gen = new SMIMESignedGenerator();
            var certStore = new JcaCertStore(Collections.singletonList(this.publicCert));
            gen.addCertificates(certStore);

            logger.debug("Using hash algorithm: {}", signatureAlg);

            gen.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder()
                            .setProvider(BOUNCY_CASTLE_PROVIDER).build())
                            .build(
                                    new JcaContentSignerBuilder(signatureAlg)
                                            .setProvider(BOUNCY_CASTLE_PROVIDER)
                                            .build(this.privateKey),
                                    this.publicCert
                            )
            );

            return gen.generate(payloadPart);
        } catch (
                MessagingException |
                SMIMEException |
                OperatorCreationException |
                CertificateEncodingException exception
        ) {
            throw new AS2Exception("Payload sign error", exception);
        }
    }

    /**
     * Encrypts a signed payload for the recipient.
     *
     * @param signedPayload      the signed MIME multipart to encrypt
     * @param receiverPublicCert the recipient's public certificate for encryption
     * @param encryptionAlg      the encryption algorithm identifier
     * @return DER-encoded encrypted data
     * @throws AS2Exception if encryption fails
     */
    private byte[] encryptPayload(
            MimeMultipart signedPayload, X509Certificate receiverPublicCert, ASN1ObjectIdentifier encryptionAlg) {
        try {
            logger.debug("Encoding payload using encryption algorithm: {}", encryptionAlg.getId());

            var wrapperPart = new MimeBodyPart();
            wrapperPart.setContent(signedPayload);
            wrapperPart.setHeader("Content-Type", signedPayload.getContentType());

            var outputStream = new ByteArrayOutputStream();
            wrapperPart.writeTo(outputStream);
            var signedBytes = outputStream.toByteArray();

            // Create CMS EnvelopedData
            var gen = new CMSEnvelopedDataGenerator();
            gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(receiverPublicCert).
                    setProvider(BOUNCY_CASTLE_PROVIDER));

            var cmsData = gen.generate(
                    new CMSProcessableByteArray(signedBytes),
                    new JceCMSContentEncryptorBuilder(encryptionAlg)
                            .setProvider(BOUNCY_CASTLE_PROVIDER).build()
            );

            // DER encoded
            return cmsData.getEncoded();
        } catch (MessagingException | CertificateEncodingException | CMSException | IOException exception) {
            throw new AS2Exception("Encryption failure", exception);
        }
    }
}