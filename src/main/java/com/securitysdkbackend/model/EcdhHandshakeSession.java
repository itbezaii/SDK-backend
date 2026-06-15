package com.securitysdkbackend.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;
import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
@RedisHash("EcdhHandshakeSession")
public class EcdhHandshakeSession implements Serializable {
    @Id
    private String sessionId; // Identifiant unique du handshake
    private String serverPrivateKeyBase64; // Clé privée du serveur
    @TimeToLive
    private Long timeoutInSeconds; // Temps avant destruction automatique
}
