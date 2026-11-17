package ru.demo.crypto.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record DecryptRequest(
        @NotBlank @Size(max = 20) String version,
        @NotBlank @Size(max = 100) String nonce,
        @NotBlank @Size(max = 50000) String ciphertext
) {
}
