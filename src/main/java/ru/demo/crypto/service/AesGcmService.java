package ru.demo.crypto.service;

import org.springframework.stereotype.Service;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class AesGcmService {
    public static final String FORMAT_VERSION = "v1";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final SecretKey key;
    private final SecureRandom secureRandom;

    public AesGcmService(SecretKey key) {
        this(key, new SecureRandom());
    }

    AesGcmService(SecretKey key, SecureRandom secureRandom) {
        this.key = key;
        this.secureRandom = secureRandom;
    }

    public EncryptedPayload encrypt(String plaintext) {
        byte[] nonce = new byte[NONCE_BYTES];
        secureRandom.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return new EncryptedPayload(FORMAT_VERSION,
                    Base64.getEncoder().encodeToString(nonce),
                    Base64.getEncoder().encodeToString(encrypted));
        } catch (GeneralSecurityException exception) {
            throw new CryptoOperationException("Encryption failed", exception);
        }
    }

    public String decrypt(String version, String encodedNonce, String encodedCiphertext) {
        if (!FORMAT_VERSION.equals(version)) {
            throw new CryptoOperationException("Unsupported encrypted payload version");
        }

        try {
            byte[] nonce = Base64.getDecoder().decode(encodedNonce);
            byte[] ciphertext = Base64.getDecoder().decode(encodedCiphertext);
            if (nonce.length != NONCE_BYTES) {
                throw new CryptoOperationException("Invalid nonce length");
            }
            if (ciphertext.length < TAG_BITS / Byte.SIZE) {
                throw new CryptoOperationException("Invalid ciphertext length");
            }

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (AEADBadTagException exception) {
            throw new CryptoOperationException("Ciphertext authentication failed", exception);
        } catch (IllegalArgumentException exception) {
            throw new CryptoOperationException("Encrypted payload contains invalid Base64", exception);
        } catch (GeneralSecurityException exception) {
            throw new CryptoOperationException("Decryption failed", exception);
        }
    }

    public record EncryptedPayload(String version, String nonce, String ciphertext) {
    }
}
