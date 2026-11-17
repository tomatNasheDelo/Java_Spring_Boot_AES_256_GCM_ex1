package ru.demo.crypto.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Configuration
public class CryptoKeyConfig {
    private static final int AES_256_KEY_BYTES = 32;

    @Bean
    public SecretKey aesSecretKey(@Value("${app.crypto.key-base64}") String encodedKey) {
        final byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(encodedKey);
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException("app.crypto.key-base64 must be valid Base64", exception);
        }
        if (keyBytes.length != AES_256_KEY_BYTES) {
            throw new IllegalStateException("AES-256 key must decode to exactly 32 bytes");
        }
        return new SecretKeySpec(keyBytes, "AES");
    }
}
