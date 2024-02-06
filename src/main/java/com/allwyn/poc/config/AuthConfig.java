package com.allwyn.poc.config;

import java.io.UnsupportedEncodingException;

import com.allwyn.poc.controller.LogoutController;
import com.allwyn.poc.validator.AudienceValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.oauth2.jwt.Jwt;

import com.auth0.AuthenticationController;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;

import javax.servlet.http.HttpServletRequest;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AuthConfig {

    @Value(value = "${com.auth0.domain}")
    private String domain;

    @Value(value = "${com.auth0.clientId}")
    private String clientId;

    @Value(value = "${com.auth0.clientSecret}")
    private String clientSecret;

    @Value(value = "${com.auth0.managementApi.clientId}")
    private String managementApiClientId;

    @Value(value = "${com.auth0.managementApi.clientSecret}")
    private String managementApiClientSecret;

    @Value(value = "${com.auth0.managementApi.grantType}")
    private String grantType;

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return new LogoutController();
    }

    @Bean
    public AuthenticationController authenticationController() throws UnsupportedEncodingException {
        JwkProvider jwkProvider = new JwkProviderBuilder(domain).build();
        return AuthenticationController.newBuilder(domain, clientId, clientSecret)
                .withJwkProvider(jwkProvider)
                .build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf()
                .disable()
                .authorizeRequests()
                    //.antMatchers("/users").hasAuthority("SCOPE_users")
                    //.antMatchers("/userByEmail").hasAuthority("SCOPE_userByEmail")
                    .antMatchers("/callback", "/login", "/")
                    .permitAll()
                    .anyRequest()
                    .authenticated()
                .and()
                .formLogin()
                    .loginPage("/login")
                .and()
                .logout()
                    .logoutSuccessHandler(logoutSuccessHandler())
                    .permitAll()
                .and()
                .oauth2ResourceServer()
                    .jwt()
                    .decoder(jwtDecoder())
                    .jwtAuthenticationConverter(jwtAuthenticationConverter());;
        return http.build();
    }

    public String getDomain() {
        return domain;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getManagementApiClientId() {
        return managementApiClientId;
    }

    public String getManagementApiClientSecret() {
        return managementApiClientSecret;
    }

    public String getGrantType() {
        return grantType;
    }

    public String getUserInfoUrl() {
        return "https://" + getDomain() + "/userinfo";
    }

    public String getUsersUrl() {
        return "https://" + getDomain() + "/api/v2/users";
    }

    public String getUsersByEmailUrl() {
        return "https://" + getDomain() + "/api/v2/users-by-email?email=";
    }

    public String getLogoutUrl() {
        return "https://" + getDomain() +"/v2/logout";
    }

    public String getContextPath(HttpServletRequest request) {
        String path = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();
        return path;
    }

    JwtDecoder jwtDecoder() {
        String issuer = "https://" + domain + "/";
        OAuth2TokenValidator<Jwt> withAudience = new AudienceValidator("http://localhost:8090");
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
        OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(withAudience, withIssuer);

        NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromOidcIssuerLocation(issuer);
        jwtDecoder.setJwtValidator(validator);
        return jwtDecoder;
    }

    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
        converter.setAuthoritiesClaimName("permissions");
        converter.setAuthorityPrefix("");

        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(converter);
        return jwtConverter;
    }
}
