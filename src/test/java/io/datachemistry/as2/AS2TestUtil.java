package io.datachemistry.as2;

import java.io.IOException;
import java.util.Base64;

/**
 * @author entropywhisperer
 */
public class AS2TestUtil {
    public static String getBase64PemContent(Class<?> clazz, String pemFile) {
        try (var resourceStream = clazz.getClassLoader().getResourceAsStream(pemFile)) {
            if (resourceStream == null) {
                throw new RuntimeException("Resource not found: " + pemFile);
            }
            return Base64.getEncoder().encodeToString(resourceStream.readAllBytes());
        } catch (IOException exception) {
            throw new RuntimeException("Unable to read PEM file", exception);
        }
    }

    public static byte[] getPemContent(Class<?> clazz, String pemFile) {
        try (var resourceStream = clazz.getClassLoader().getResourceAsStream(pemFile)) {
            if (resourceStream == null) {
                throw new RuntimeException("Resource not found: " + pemFile);
            }
            return resourceStream.readAllBytes();
        } catch (IOException exception) {
            throw new RuntimeException("Unable to read PEM file", exception);
        }
    }
}
