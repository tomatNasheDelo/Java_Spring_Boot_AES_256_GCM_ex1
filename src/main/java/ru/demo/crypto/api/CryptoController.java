package ru.demo.crypto.api;

import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.demo.crypto.service.AesGcmService;
import ru.demo.crypto.service.AesGcmService.EncryptedPayload;

@RestController
@RequestMapping("/api/crypto")
public class CryptoController {
    private final AesGcmService cryptoService;

    public CryptoController(AesGcmService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @PostMapping("/encrypt")
    public EncryptResponse encrypt(@Valid @RequestBody EncryptRequest request) {
        EncryptedPayload encrypted = cryptoService.encrypt(request.plaintext());
        return new EncryptResponse(encrypted.version(), encrypted.nonce(), encrypted.ciphertext());
    }

    @PostMapping("/decrypt")
    public DecryptResponse decrypt(@Valid @RequestBody DecryptRequest request) {
        return new DecryptResponse(cryptoService.decrypt(
                request.version(), request.nonce(), request.ciphertext()));
    }
}
