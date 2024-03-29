package com.allwyn.poc.controller;

import java.io.IOException;
import java.util.HashMap;

import com.allwyn.poc.config.AuthConfig;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;

import com.auth0.AuthenticationController;
import com.auth0.IdentityVerificationException;
import com.auth0.Tokens;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class AuthController {

    @Autowired
    private AuthenticationController authenticationController;

    @Autowired
    private AuthConfig config;

    @GetMapping(value = "/login")
    protected void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUri = config.getContextPath(request) + "/callback";
        String authorizeUrl = authenticationController.buildAuthorizeUrl(request, response, redirectUri)
                .withAudience("http://localhost:8090")
                .withScope("openid profile email")
                .build();
        response.sendRedirect(authorizeUrl);
    }

    @GetMapping(value="/callback")
    public void callback(HttpServletRequest request, HttpServletResponse response) throws IOException, IdentityVerificationException {
        Tokens tokens = authenticationController.handle(request, response);

        DecodedJWT jwt = JWT.decode(tokens.getIdToken());
        TestingAuthenticationToken authToken2 = new TestingAuthenticationToken(jwt.getSubject(), jwt.getToken());
        authToken2.setAuthenticated(true);

        //TODO remove, this is just for testing
        System.out.println("\n\n Access token: \n Bearer " + tokens.getAccessToken() +"\n\n");

        SecurityContextHolder.getContext().setAuthentication(authToken2);
        response.sendRedirect(config.getContextPath(request) + "/");
    }

    public String getManagementApiToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        JSONObject requestBody = new JSONObject();
        requestBody.put("client_id", config.getManagementApiClientId());
        requestBody.put("client_secret", config.getManagementApiClientSecret());
        requestBody.put("audience", "https://" + config.getDomain() +"/api/v2/");

        requestBody.put("grant_type", config.getGrantType());

        HttpEntity<String> request = new HttpEntity<String>(requestBody.toString(), headers);

        RestTemplate restTemplate = new RestTemplate();
        HashMap<String, String> result = restTemplate.postForObject("https://" + config.getDomain() +"/oauth/token", request, HashMap.class);

        return result.get("access_token");
    }

}