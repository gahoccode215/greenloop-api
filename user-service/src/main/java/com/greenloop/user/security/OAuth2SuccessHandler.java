package com.greenloop.user.security;

import com.greenloop.user.entity.Role;
import com.greenloop.user.entity.User;
import com.greenloop.user.repository.RoleRepository;
import com.greenloop.user.repository.UserRepository;
import com.greenloop.user.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtUtil jwtUtil;
    private final RedisTemplate<String, Object> redisObjectTemplate;

    @Value("${app.oauth2.frontend-redirect-url:http://localhost:5173/auth/callback}")
    private String frontendRedirectUrl;

    @Override
    @Transactional
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
//        String picture = oAuth2User.getAttribute("picture");

        String roleName =
                oAuth2User.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .filter(auth -> auth.startsWith("ROLE_"))
                        .findFirst()
                        .map(auth -> auth.substring(5))
                        .orElse("CUSTOMER");

        log.info("OAuth2 login successful for email: {} with role: {}", email, roleName);

        User user =
                userRepository
                        .findByEmail(email)
                        .map(existingUser -> handleExistingUser(existingUser, name))
                        .orElseGet(() -> createNewGoogleUser(email, name, roleName));

        List<String> roles = user.getRoles().stream().map(Role::getName).toList();

        String accessToken = jwtUtil.generateToken(user);
        String refreshToken = jwtUtil.generateRefreshToken(user);

        String tempKey = UUID.randomUUID().toString();
        Map<String, Object> tokenData = new HashMap<>();
        tokenData.put("accessToken", accessToken);
        tokenData.put("refreshToken", refreshToken);
        tokenData.put("type", "Bearer");
        tokenData.put("userId", user.getId());
        tokenData.put("email", user.getEmail());
        tokenData.put("roles", roles);
        tokenData.put("expiresIn", jwtUtil.getExpirationTime());
        tokenData.put("refreshExpiresIn", jwtUtil.getRefreshExpirationTime());

        String redisKey = "oauth2_success:" + tempKey;
        redisObjectTemplate.opsForValue().set(redisKey, tokenData, 5, TimeUnit.MINUTES);

        String redirectUrl = frontendRedirectUrl + "?key=" + tempKey;
        log.info("Redirecting to: {}", redirectUrl);
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }

    private User createNewGoogleUser(String email, String name, String roleName) {
        Role role =
                roleRepository
                        .findByName(roleName)
                        .orElseGet(
                                () ->
                                        roleRepository
                                                .findByName("CUSTOMER")
                                                .orElseThrow(() -> new RuntimeException("Role CUSTOMER not found")));

        User newUser =
                User.builder()
                        .email(email)
                        .fullName(name)
                        .roles(List.of(role))
                        .isEmailVerified(true)
                        .provider("GOOGLE")
                        .password("") // Password trống cho GOOGLE-only users
                        .isActive(true)
                        .build();

        User savedUser = userRepository.save(newUser);
        log.info("Created new Google user: {} with provider: GOOGLE", email);
        return savedUser;
    }

    private User handleExistingUser(User existingUser, String name) {
        // Cập nhật thông tin profile
        if (name != null && !name.equals(existingUser.getFullName())) {
            existingUser.setFullName(name);
        }

        existingUser.setActive(true);
        existingUser.setIsEmailVerified(true);

        // Xử lý provider logic
        String currentProvider = existingUser.getProvider();

        if ("LOCAL".equals(currentProvider)) {
            // User đã đăng ký bằng email/password, giờ login bằng Google
            // => Upgrade thành BOTH
            existingUser.setProvider("BOTH");
            log.info("Upgraded user {} from LOCAL to BOTH provider", existingUser.getEmail());

        } else if ("GOOGLE".equals(currentProvider)) {
            // User vẫn chỉ dùng Google, giữ nguyên
            log.info("User {} continues using GOOGLE provider", existingUser.getEmail());

        } else if ("BOTH".equals(currentProvider)) {
            // Đã có BOTH rồi, không cần thay đổi
            log.info("User {} already has BOTH provider", existingUser.getEmail());
        }

        User updatedUser = userRepository.save(existingUser);
        return updatedUser;
    }
}
