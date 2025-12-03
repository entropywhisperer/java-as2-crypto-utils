package io.datachemistry.as2.exception;

/**
 * @author entropywhisperer
 */
public class AS2Exception extends RuntimeException {

    public AS2Exception(String message) {
        super(message);
    }

    public AS2Exception(String message, Throwable cause) {
        super(message, cause);
    }

    public AS2Exception(Throwable cause) {
        super(cause);
    }
}
