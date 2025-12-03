package io.datachemistry.as2.model;

/**
 * @author entropywhisperer
 */
public final class AS2Constant {
    private AS2Constant() {
        throw new UnsupportedOperationException("Cannot instantiate constants class");
    }

    public static final String ENCRYPT_CONTENT_TYPE = "application/xml";
    public static final String DECRYPT_CONTENT_TYPE = "multipart/signed";
}
