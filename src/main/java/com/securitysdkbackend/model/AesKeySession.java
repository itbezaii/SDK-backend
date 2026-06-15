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
@RedisHash("AesKeySession")
public class AesKeySession implements Serializable {
    @Id
    private String sessionId; // UUID renvoyé à Flutter (identifiant de session)
    private String aesKeyBase64; // Clé AES-256 finale
    @TimeToLive
    private Long timeoutInSeconds; // Durée de validité de la session
}
