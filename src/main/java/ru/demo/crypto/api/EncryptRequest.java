package ru.demo.crypto.api;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record EncryptRequest(
        @NotNull
        @Size(max = 16000, message = "plaintext must be at most 16000 characters")
        String plaintext
) {
}
