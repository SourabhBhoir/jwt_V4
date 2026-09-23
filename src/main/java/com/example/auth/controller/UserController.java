package com.example.auth.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class UserController {

    @GetMapping("/api/me")
    public Map<String, Object> me(Authentication authentication) {
        return Map.of(
                "message", "JWT is valid. You are authenticated.",
                "email", authentication.getName(),
                "authorities", authentication.getAuthorities()
        );
    }
}
