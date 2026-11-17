package ru.demo.crypto.api;

public record EncryptResponse(String version, String nonce, String ciphertext) {
}
