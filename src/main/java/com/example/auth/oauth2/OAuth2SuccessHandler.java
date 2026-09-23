package com.example.auth.oauth2;

import com.example.auth.dto.AuthResponse;
import com.example.auth.model.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.JwtService;
import com.example.auth.service.AuthService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final AuthService authService;
    private final String frontendCallback;

    public OAuth2SuccessHandler(
            UserRepository userRepository,
            AuthService authService,
            @Value("${app.oauth2.frontend-callback}") String frontendCallback) {
        this.userRepository = userRepository;
        this.authService = authService;
        this.frontendCallback = frontendCallback;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();
        String email = oauthUser.getAttribute("email");
        String name = oauthUser.getAttribute("name");

        if (email == null) {
            response.sendError(400, "Google account did not provide an email");
            return;
        }

        User user = userRepository.findByEmail(email).orElseGet(() -> {
            User newUser = new User();
            newUser.setName(name != null ? name : email);
            newUser.setEmail(email);
            newUser.setProvider("GOOGLE");
            newUser.setRole("USER");
            return userRepository.save(newUser);
        });

        AuthResponse authResponse = authService.createAuthResponse(user);

        String target = UriComponentsBuilder
                .fromUriString(frontendCallback)
                .queryParam("token", authResponse.token())
                .queryParam("refreshToken", authResponse.refreshToken())
                .build()
                .toUriString();

        getRedirectStrategy().sendRedirect(request, response, target);
    }
}
