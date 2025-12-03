package io.datachemistry.as2.crypto;

import io.datachemistry.as2.exception.AS2Exception;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.security.PrivateKey;

/**
 * Utility class for managing private keys.
 *
 * @author entropywhisperer
 */
final class KeyManager {
    private static final String BOUNCY_CASTLE_PROVIDER = "BC";

    private KeyManager() {
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * Loads a private key from encrypted PEM data.
     *
     * @param privateKey    the PEM-encoded private key data
     * @param keyPassphrase the passphrase to decrypt the private key
     * @return the loaded private key
     * @throws AS2Exception if the key data is invalid, cannot be decrypted, or parsed
     */
    public static PrivateKey getPrivateKey(byte[] privateKey, char[] keyPassphrase) throws AS2Exception {
        try (var pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(privateKey)))) {
            var pemObject = pemParser.readObject();
            var converter = new JcaPEMKeyConverter().setProvider(BOUNCY_CASTLE_PROVIDER);

            if (pemObject instanceof PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo) {
                var provider = new JcePKCSPBEInputDecryptorProviderBuilder().setProvider(
                        BOUNCY_CASTLE_PROVIDER).build(keyPassphrase);
                return converter.getPrivateKey(encryptedPrivateKeyInfo.decryptPrivateKeyInfo(provider));
            }

            throw new IllegalStateException("Unexpected PEM object type: " + pemObject.getClass().getName());
        } catch (Exception exception) {
            throw new AS2Exception("Invalid private key", exception);
        }
    }
}