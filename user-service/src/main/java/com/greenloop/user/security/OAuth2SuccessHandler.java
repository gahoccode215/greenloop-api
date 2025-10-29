package com.greenloop.user.security;

import com.greenloop.user.entity.Role;
import com.greenloop.user.entity.User;
import com.greenloop.user.repository.RoleRepository;
import com.greenloop.user.repository.UserRepository;
import com.greenloop.user.util.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
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
      throws IOException, ServletException {

    OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

    String email = oAuth2User.getAttribute("email");
    String name = oAuth2User.getAttribute("name");
    String picture = oAuth2User.getAttribute("picture");

    // Lấy role từ authorities
    String roleName =
        oAuth2User.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .filter(auth -> auth.startsWith("ROLE_"))
            .findFirst()
            .map(auth -> auth.substring(5)) // Bỏ "ROLE_" prefix
            .orElse("CUSTOMER");

    log.info("OAuth2 login successful for email: {} with role: {}", email, roleName);

    // Tìm hoặc tạo user trong database
    User user =
        userRepository
            .findByEmail(email)
            .map(existingUser -> updateExistingUser(existingUser, name, picture))
            .orElseGet(() -> createNewGoogleUser(email, name, picture, roleName));

    // Generate JWT tokens
    String accessToken = jwtUtil.generateToken(user);
    String refreshToken = jwtUtil.generateRefreshToken(user);

    // Tạo temporary key
    String tempKey = UUID.randomUUID().toString();
    Map<String, Object> tokenData = new HashMap<>();
    tokenData.put("accessToken", accessToken);
    tokenData.put("refreshToken", refreshToken);
    tokenData.put("type", "Bearer");
    tokenData.put("userId", user.getId());
    tokenData.put("email", user.getEmail());
    tokenData.put("role", user.getRole().getName());
    tokenData.put("expiresIn", jwtUtil.getExpirationTime());
    tokenData.put("refreshExpiresIn", jwtUtil.getRefreshExpirationTime());

    // Lưu vào Redis với TTL 5 phút
    String redisKey = "oauth2_success:" + tempKey;
    redisObjectTemplate.opsForValue().set(redisKey, tokenData, 5, TimeUnit.MINUTES);

    // Redirect về frontend với temporary key
    String redirectUrl = frontendRedirectUrl + "?key=" + tempKey;
    log.info("Redirecting to: {}", redirectUrl);
    getRedirectStrategy().sendRedirect(request, response, redirectUrl);
  }

  private User createNewGoogleUser(String email, String name, String picture, String roleName) {
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
            .role(role)
            .isActive(true)
            .isEmailVerified(true)
            .provider("GOOGLE")
            .build();

    User savedUser = userRepository.save(newUser);
    log.info("Created new Google user: {} with role: {}", email, role.getName());
    return savedUser;
  }

  private User updateExistingUser(User existingUser, String name, String picture) {
    // Cập nhật thông tin nếu cần
    if (name != null && !name.equals(existingUser.getFullName())) {
      existingUser.setFullName(name);
    }

    // Đảm bảo user active và email verified
    existingUser.setIsActive(true);
    existingUser.setIsEmailVerified(true);

    User updatedUser = userRepository.save(existingUser);
    log.info("Updated existing Google user: {}", existingUser.getEmail());
    return updatedUser;
  }
}
