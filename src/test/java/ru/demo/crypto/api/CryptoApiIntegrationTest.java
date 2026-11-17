package ru.demo.crypto.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "app.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
@AutoConfigureMockMvc
class CryptoApiIntegrationTest {
    @Autowired
    private MockMvc mockMvc;

    @Test
    void encryptThenDecryptThroughHttpApi() throws Exception {
        String encryptedResponse = mockMvc.perform(post("/api/crypto/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"plaintext":"hello from integration test"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value("v1"))
                .andReturn().getResponse().getContentAsString();

        com.fasterxml.jackson.databind.JsonNode encrypted =
                new com.fasterxml.jackson.databind.ObjectMapper().readTree(encryptedResponse);

        mockMvc.perform(post("/api/crypto/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"version":"%s","nonce":"%s","ciphertext":"%s"}
                                """.formatted(encrypted.get("version").asText(),
                                encrypted.get("nonce").asText(), encrypted.get("ciphertext").asText())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.plaintext").value("hello from integration test"));
    }

    @Test
    void invalidPayloadReturnsBadRequest() throws Exception {
        mockMvc.perform(post("/api/crypto/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"version":"v1","nonce":"not-base64!","ciphertext":"also-not-base64!"}
                                """))
                .andExpect(status().isBadRequest());
    }
}
