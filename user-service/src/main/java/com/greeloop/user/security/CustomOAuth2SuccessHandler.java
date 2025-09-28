package com.greeloop.user.security;

import com.greeloop.user.entity.User;
import com.greeloop.user.repository.UserRepository;
import com.greeloop.user.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final RedisTemplate<String, Object> redisTemplate;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        try {
            DefaultOAuth2User oauth2User = (DefaultOAuth2User) authentication.getPrincipal();
            String email = oauth2User.getAttribute("email");

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found after OAuth2 authentication"));

            if (!user.getIsActive()) {
                log.warn("Inactive user attempted login: {}", email);
                response.sendRedirect("http://localhost:5173/login?error=account_disabled");
                return;
            }

            String accessToken = jwtUtil.generateToken(user);
            String refreshToken = jwtUtil.generateRefreshToken(user);
            String tempKey = UUID.randomUUID().toString();

            Map<String, Object> tokenData = Map.of(
                    "accessToken", accessToken,
                    "refreshToken", refreshToken,
                    "userId", user.getId(),
                    "email", user.getEmail(),
                    "role", user.getRole().getName(),
                    "type", "Bearer",
                    "expiresIn", jwtUtil.getExpirationTime(),
                    "refreshExpiresIn", jwtUtil.getRefreshExpirationTime()
            );

            redisTemplate.opsForValue().set(
                    "oauth2_success:" + tempKey,
                    tokenData,
                    Duration.ofMinutes(5)
            );
            log.info("User logged in via Google OAuth2: {}, tempKey: {}", user.getEmail(), tempKey);

            response.sendRedirect("http://localhost:5173/oauth2/success?key=" + tempKey);


        } catch (Exception e) {
            log.error("OAuth2 authentication success handling failed", e);
            response.sendRedirect("http://localhost:5173/login?error=authentication_failed");
        }
    }

}
