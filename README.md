# as2-crypto-utils

# AS2 Crypto Library

A lightweight Java library for **encrypting, signing, decrypting, and verifying AS2 messages** using **Bouncy Castle**.  
Provides simple APIs for S/MIME signing, CMS encryption, certificate loading, and private key management.

---

## Usage

### Register Bouncy Castle security provider
```java
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

Security.addProvider(new BouncyCastleProvider());
```

### Encryption Example

```java
import io.datachemistry.as2.config.EncryptionConfig;
import io.datachemistry.as2.config.SignatureAlgorithm;
import io.datachemistry.as2.config.EncryptionAlgorithm;
import io.datachemistry.as2.crypto.AS2Encryptor;
import io.datachemistry.as2.model.AS2Constant;

// 1. Configure your certificates and keys
var config = EncryptionConfig.builder()
        .privateKey(yourPrivateKeyBase64)           // Your private key in Base64
        .privateKeyPassphrase("yourPassphrase".toCharArray())     // Passphrase for the private key
        .publicCert(yourPublicCertBase64)           // Your public certificate in Base64
        .receiverPublicCert(receiverCertBase64)     // Receiver's public certificate in Base64
        .build();

// 2. Create the encryptor
var encryptor = new AS2Encryptor(config);

// 3. Encrypt your message
byte[] message = "<root>Hello, this is a secure message</root>".getBytes(StandardCharsets.UTF_8);

byte[] encryptedData = encryptor.signAndEncryptMessage(
        message,                          // Your message bytes
        SignatureAlgorithm.SHA256_WITH_RSA,  // Signature algorithm
        EncryptionAlgorithm.AES_256_CBC,     // Encryption algorithm  
        AS2Constant.ENCRYPT_CONTENT_TYPE     // Content type
);
```
## Decryption Example

```java
import io.datachemistry.as2.config.DecryptionConfig;
import io.datachemistry.as2.crypto.AS2Decryptor;
import io.datachemistry.as2.model.AS2Constant;

// 1. Configure decryption with your receiver credentials
var config = DecryptionConfig.builder()
        .privateKey(yourPrivateKeyBase64)        // Your private key (for decryption) in Base64
        .privateKeyPassphrase("yourPassphrase".toCharArray())  // Passphrase for your private key
        .senderPublicCert(senderCertBase64)      // Sender's public certificate (for signature verification) in Base64
        .build();

// 2. Create the decryptor
var decryptor = new AS2Decryptor(config);

// 3. Decrypt received message
byte[] decryptedData = decryptor.decryptAndVerifyMessage(
        receivedEncryptedBytes,        // Encrypted data you received
        AS2Constant.DECRYPT_CONTENT_TYPE  // Decrypt content type
);

// 4. Convert to usable format
var originalMessage = new String(decryptedData, StandardCharsets.UTF_8);
```

See [`AS2RoundTripIT.java`](src/test/java/io/datachemistry/as2/integration/AS2RoundTripIT.java) for a complete working example of:
1. Loading PEM-formatted certificates
2. Encrypting and signing a message
3. Decrypting and verifying the signature

## License

Licensed under the **MIT License**. See the [`LICENSE`](LICENSE) file for details.
