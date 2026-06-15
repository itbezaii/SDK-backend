package com.securitysdkbackend.config;

import com.securitysdkbackend.filter.AppCheckFilter;
import com.securitysdkbackend.filter.IAppCheckTokenVerifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final IAppCheckTokenVerifier appCheckTokenVerifier;

    public SecurityConfig(IAppCheckTokenVerifier appCheckTokenVerifier) {
        this.appCheckTokenVerifier = appCheckTokenVerifier;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // 1. Désactivation CSRF (API stateless mobile)
                .csrf(AbstractHttpConfigurer::disable)

                // 2. Pas de session côté serveur
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // 3. Règles d'autorisation
                .authorizeHttpRequests(auth -> auth
                        // Routes publiques sans token AppCheck
                        .requestMatchers("/api/public/**", "/actuator/health").permitAll()
                        // Tout le reste nécessite AppCheck
                        .anyRequest().authenticated()
                )

                // 4. Notre filtre AppCheck
                .addFilterBefore(
                        new AppCheckFilter(appCheckTokenVerifier),
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }
}