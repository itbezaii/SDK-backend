package com.securitysdkbackend.filter;

import com.securitysdkbackend.filter.IAppCheckTokenVerifier;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Slf4j
@RequiredArgsConstructor
public class AppCheckFilter extends OncePerRequestFilter {

    private final IAppCheckTokenVerifier appCheckTokenVerifier;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        log.info("AppCheckFilter → {} {}",
                request.getMethod(),
                request.getRequestURI()
        );

        // 1. Récupérer le token AppCheck du header
        String appCheckToken = request.getHeader("X-Firebase-AppCheck");

        // 2. Token absent → 401
        if (appCheckToken == null || appCheckToken.isBlank()) {
            log.warn("Token AppCheck absent");
            handleErrorResponse(response, "Token AppCheck manquant");
            return;
        }

        // 3. Vérifier le token
        try {
            String appId = appCheckTokenVerifier.verifyToken(appCheckToken);
            log.info("Token AppCheck valide pour app : {}", appId);

            // 4. Informer Spring Security que la requête est authentifiée
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            appId,        // principal = app ID
                            null,         // credentials = null
                            Collections.emptyList() // pas de rôles
                    );
            SecurityContextHolder.getContext()
                    .setAuthentication(authentication);

            // 5. Token valide → passer au Controller
            filterChain.doFilter(request, response);

        } catch (JwtException e) {
            log.warn("Token AppCheck invalide : {}", e.getMessage());
            // Nettoyer le contexte de sécurité
            SecurityContextHolder.clearContext();
            handleErrorResponse(response, "Token AppCheck invalide");
        }
    }

    private void handleErrorResponse(
            HttpServletResponse response,
            String message
    ) throws IOException {

        // Évite d'écrire deux fois dans le flux
        if (response.isCommitted()) {
            log.warn("Réponse déjà envoyée");
            return;
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(
                "{\"error\": \"" + message + "\"}"
        );
        response.flushBuffer();
    }
}