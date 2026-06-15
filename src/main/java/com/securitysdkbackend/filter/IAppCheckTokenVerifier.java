package com.securitysdkbackend.filter;

import io.jsonwebtoken.JwtException;

public interface IAppCheckTokenVerifier {
    /**
     * Vérifie un token AppCheck Firebase.
     * @param token le token JWT AppCheck
     * @return L'app ID si valide
     * @throws JwtException si invalide, expiré ou mauvais projet
     */
    String verifyToken(String token) throws JwtException;
}
