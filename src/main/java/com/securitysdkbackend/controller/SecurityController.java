package com.securitysdkbackend.controller;

import com.securitysdkbackend.model.AesKeySession;
import com.securitysdkbackend.repository.AesKeySessionRepository;
import com.securitysdkbackend.service.IEcdhService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/security")
@RequiredArgsConstructor
public class SecurityController {

    private final IEcdhService ecdhService;
    private final AesKeySessionRepository aesKeyRepository;

    private static final long AES_KEY_TTL_SECONDS = 60L; // pour test, a changer a 1h!!

    @PostMapping("/secure-data")
    public ResponseEntity<Map<String, String>> handleSecureData(
            @RequestHeader("X-Session-Id") String sessionId,
            @RequestBody Map<String, String> encryptedPayload
    ) {
        try {
            // 1. Validation du sessionId
            if (sessionId == null || sessionId.isBlank()) {
                log.warn("Requête refusée : X-Session-Id absent");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            // 2. Récupération de la clé AES depuis Redis
            AesKeySession aesKeySession = aesKeyRepository
                    .findById(sessionId)
                    .orElse(null);

            if (aesKeySession == null) {
                log.warn("Session introuvable ou expirée pour sessionId : {}", sessionId);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Session expirée. Veuillez refaire le handshake."));
            }

            // 3. Reconstruction de la SecretKey AES
            byte[] keyBytes = Base64.getDecoder().decode(aesKeySession.getAesKeyBase64());
            SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

            // Mettre à jour la fenêtre glissante (Sliding TTL) via Spring Data Redis.
            // On réassigne le TTL initial et on sauvegarde l'entité.
            // Spring se charge de recalculer et mettre à jour les bons index dans Redis de manière transparente.
            aesKeySession.setTimeoutInSeconds(AES_KEY_TTL_SECONDS);
            aesKeyRepository.save(aesKeySession);
            log.debug("TTL Redis nativement remis à 1 heure via repository pour sessionId : {}", sessionId);

            // 5. Déchiffrement de la payload reçue de Flutter
            String plainText = ecdhService.decrypt(encryptedPayload, aesKey);
            log.info("Payload déchiffrée avec succès : {}", plainText);

            // 6. Traitement métier
            String responseText = "Serveur a bien reçu : " + plainText;

            // 7. Rechiffrement de la réponse
            Map<String, String> encryptedResponse = ecdhService.encrypt(responseText, aesKey);
            log.debug("Réponse rechiffrée et prête à être envoyée ");

            return ResponseEntity.ok(encryptedResponse);

        } catch (Exception e) {
            log.error("Erreur lors du traitement de la requête sécurisée", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
