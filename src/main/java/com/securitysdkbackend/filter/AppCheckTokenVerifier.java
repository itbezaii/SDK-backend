package com.securitysdkbackend.filter;

import com.auth0.jwk.*;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;
import java.util.List;

@Slf4j
@Component
public class AppCheckTokenVerifier implements IAppCheckTokenVerifier {

    private static final String JWKS_URL =
            "https://firebaseappcheck.googleapis.com/v1/jwks";
    private static final String REQUIRED_ALGORITHM = "RS256";
    private static final String REQUIRED_TYPE = "JWT";

    @Value("${firebase.project-number}")
    private String projectNumber;

    private final JwkProvider provider;

    public AppCheckTokenVerifier() {
        try {
            this.provider = new GuavaCachedJwkProvider(
                    new UrlJwkProvider(new URL(JWKS_URL))
            );
        } catch (MalformedURLException e) {
            log.error("URL JWKS invalide", e);
            throw new RuntimeException("URL JWKS invalide", e);
        }
    }

    @Override
    public String verifyToken(String token) throws JwtException {

        String expectedIssuer =
                "https://firebaseappcheck.googleapis.com/" + projectNumber;
        String expectedAudience = "projects/" + projectNumber;

        Claims claims = Jwts.parserBuilder()
                .setSigningKeyResolver(new SigningKeyResolverAdapter() {
                    @Override
                    public Key resolveSigningKey(JwsHeader header, Claims claims) {

                        // Étape 3 : vérifier algorithme RS256
                        if (!REQUIRED_ALGORITHM.equals(header.getAlgorithm())) {
                            throw new JwtException(
                                    "Algorithme invalide : " + header.getAlgorithm()
                            );
                        }

                        // Étape 4 : vérifier type JWT
                        if (!REQUIRED_TYPE.equals(header.getType())) {
                            throw new JwtException(
                                    "Type invalide : " + header.getType()
                            );
                        }

                        // Étapes 1+2 : récupérer clé publique depuis JWKS
                        try {
                            String kid = header.getKeyId();
                            if (kid == null) {
                                throw new JwtException("kid manquant dans le header");
                            }
                            Jwk jwk = provider.get(kid);
                            return jwk.getPublicKey();
                        } catch (JwkException e) {
                            throw new MalformedJwtException(
                                    "Clé publique introuvable pour kid : "
                                            + header.getKeyId()
                            );
                        }
                    }
                })
                .requireIssuer(expectedIssuer)  // Étape 5
                .build()
                .parseClaimsJws(token)          // Étapes 2+6
                .getBody();

        // Étape 7 : vérifier audience manuellement
        Object audClaim = claims.get("aud");
        boolean validAudience = false;

        if (audClaim instanceof String) {
            validAudience = expectedAudience.equals(audClaim);
        } else if (audClaim instanceof List) {
            @SuppressWarnings("unchecked")
            List<String> audiences = (List<String>) audClaim;
            validAudience = audiences.contains(expectedAudience);
        }

        // Lève exception si audience invalide
        if (!validAudience) {
            throw new JwtException("Audience invalide : " + audClaim);
        }

        // Étape 8 : retourner app ID
        String appId = claims.getSubject();
        log.debug("Token AppCheck valide pour app : {}", appId);

        return appId;
    }
}