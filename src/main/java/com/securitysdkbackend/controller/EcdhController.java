package com.securitysdkbackend.controller;

import com.securitysdkbackend.service.IEcdhService;
import com.securitysdkbackend.model.AesKeySession;
import com.securitysdkbackend.model.EcdhHandshakeSession;
import com.securitysdkbackend.repository.AesKeySessionRepository;
import com.securitysdkbackend.repository.EcdhHandshakeSessionRepository;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/security")
@RequiredArgsConstructor
public class EcdhController { // <-- Correction : Plus de implements IEcdhService ici !

    private final IEcdhService ecdhService;
    private final EcdhHandshakeSessionRepository handshakeRepository;
    private final AesKeySessionRepository aesKeyRepository;

    private static final long AES_KEY_TTL_SECONDS = 60L; // pour test, a changer a 1h!!

    @Data
    public static class HandshakeRequest {
        private String clientPublicKey;
    }

    @PostMapping("/handshake")
    public ResponseEntity<Map<String, String>> handleHandshake(@RequestBody HandshakeRequest request) {
        try {
            if (request.getClientPublicKey() == null || request.getClientPublicKey().isBlank()) {
                log.warn("Handshake refusé : clé publique cliente absente");
                return ResponseEntity.badRequest().build();
            }

            // 1. Génération de la paire de clés éphémère du serveur
            KeyPair serverKeyPair = ecdhService.generateKeyPair();
            String handshakeId = UUID.randomUUID().toString();

            byte[] serverPublicKeyBytes = ecdhService.getPublicKeyBytes(serverKeyPair);
            String serverPublicKeyBase64 = Base64.getEncoder().encodeToString(serverPublicKeyBytes);

            // 2. Stockage de la clé privée dans Redis (Le Post-it)
            String privateKeyBase64 = Base64.getEncoder().encodeToString(serverKeyPair.getPrivate().getEncoded());
            handshakeRepository.save(new EcdhHandshakeSession(handshakeId, privateKeyBase64, 120L));

            // 3. Récupération pour le calcul
            EcdhHandshakeSession activeSession = handshakeRepository.findById(handshakeId)
                    .orElseThrow(() -> new IllegalStateException("Session handshake introuvable dans Redis"));

            byte[] privateKeyBytes = Base64.getDecoder().decode(activeSession.getServerPrivateKeyBase64());
            KeyFactory kf = KeyFactory.getInstance("EC","BC");
            PrivateKey recoveredPrivateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            KeyPair explicitKeyPair = new KeyPair(null, recoveredPrivateKey);

            // 4. Suppression immédiate de la clé privée de Redis (On déchire le Post-it)
            handshakeRepository.deleteById(handshakeId);
            log.debug("Clé privée éphémère détruite de Redis ");

            // 5. Calcul du secret partagé et dérivation en clé AES-256
            byte[] clientPublicKeyBytes = Base64.getDecoder().decode(request.getClientPublicKey());
            SecretKey sharedAesKey = ecdhService.computeSharedAesKey(explicitKeyPair, clientPublicKeyBytes);

            // 6. Génération de l'ID de session permanent pour Flutter
            String sessionId = UUID.randomUUID().toString();

            // 7. Enregistrement de la clé AES finale dans Redis (Le Coffre-fort)
            String aesKeyBase64 = Base64.getEncoder().encodeToString(sharedAesKey.getEncoded());
            aesKeyRepository.save(new AesKeySession(sessionId, aesKeyBase64, AES_KEY_TTL_SECONDS));
            log.info("Clé AES stockée dans Redis. SessionId : {}", sessionId);

            // 8. Envoi de la réponse à Flutter avec la clé sauvegardée à l'étape 1
            Map<String, String> response = new HashMap<>();
            response.put("serverPublicKey", serverPublicKeyBase64);
            response.put("sessionId", sessionId);
            response.put("status", "SUCCESS");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Erreur critique durant le handshake ECDH", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
