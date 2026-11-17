package ru.demo.crypto.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesGcmServiceTest {
    private AesGcmService service;

    @BeforeEach
    void setUp() {
        byte[] testOnlyKey = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        SecretKey key = new SecretKeySpec(testOnlyKey, "AES");
        service = new AesGcmService(key);
    }

    @Test
    void encryptThenDecryptRestoresUnicodePlaintext() {
        String plaintext = "Привет, AES-GCM 🔐";

        AesGcmService.EncryptedPayload encrypted = service.encrypt(plaintext);

        assertEquals(AesGcmService.FORMAT_VERSION, encrypted.version());
        assertEquals(plaintext, service.decrypt(encrypted.version(), encrypted.nonce(), encrypted.ciphertext()));
    }

    @Test
    void eachEncryptionUsesANewRandomNonce() {
        AesGcmService.EncryptedPayload first = service.encrypt("same text");
        AesGcmService.EncryptedPayload second = service.encrypt("same text");

        assertNotEquals(first.nonce(), second.nonce());
        assertNotEquals(first.ciphertext(), second.ciphertext());
    }

    @Test
    void changingCiphertextFailsAuthentication() {
        AesGcmService.EncryptedPayload encrypted = service.encrypt("important message");
        byte[] bytes = java.util.Base64.getDecoder().decode(encrypted.ciphertext());
        bytes[0] ^= 1;
        String tamperedCiphertext = java.util.Base64.getEncoder().encodeToString(bytes);

        assertThrows(CryptoOperationException.class,
                () -> service.decrypt(encrypted.version(), encrypted.nonce(), tamperedCiphertext));
    }

    @Test
    void changingNonceFailsAuthentication() {
        AesGcmService.EncryptedPayload encrypted = service.encrypt("important message");
        byte[] bytes = java.util.Base64.getDecoder().decode(encrypted.nonce());
        bytes[0] ^= 1;
        String tamperedNonce = java.util.Base64.getEncoder().encodeToString(bytes);

        assertThrows(CryptoOperationException.class,
                () -> service.decrypt(encrypted.version(), tamperedNonce, encrypted.ciphertext()));
    }

    @Test
    void rejectsUnknownPayloadVersion() {
        assertThrows(CryptoOperationException.class,
                () -> service.decrypt("v2", "AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAA=="));
    }
}
