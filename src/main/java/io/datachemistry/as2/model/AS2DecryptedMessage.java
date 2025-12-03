package io.datachemistry.as2.model;

import java.util.Arrays;
import java.util.Objects;

/**
 * Represents a decrypted AS2 message containing both raw bytes and string content.
 *
 * @author entropywhisperer
 */
public record AS2DecryptedMessage(byte[] fullPayload, String content) {
    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        var that = (AS2DecryptedMessage) o;
        return Objects.equals(content, that.content) && Objects.deepEquals(fullPayload, that.fullPayload);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(fullPayload), content);
    }

    @Override
    public String toString() {
        return "AS2DecryptedMessage{" + "fullPayload="
                + Arrays.toString(fullPayload) + ", content='" + content + '\'' + '}';
    }
}