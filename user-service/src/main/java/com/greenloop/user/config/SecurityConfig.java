package com.greenloop.user.config;

import com.greenloop.user.security.HeaderAuthFilter;
import com.greenloop.user.security.OAuth2FailureHandler;
import com.greenloop.user.security.OAuth2SuccessHandler;
import jakarta.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private static final String[] PUBLIC_ENDPOINTS = {
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/verify-email",
    "/api/v1/auth/resend-otp",
    "/api/v1/auth/refresh",
    "/api/v1/auth/forgot-password",
    "/api/v1/auth/verify-reset-otp",
    "/api/v1/auth/reset-password",
    "/api/v1/auth/change-password-first-time",
    "/api/v1/auth/resend-reset-password-otp",
    "/api/v1/auth/resend-verify-email-otp",
    "/api/v1/auth/oauth2/exchange",
    "/oauth2/**",
    "/login/**",
    "/api/v1/users/*/**",
          "/api/v1/blogs"
  };

  private final HeaderAuthFilter headerAuthFilter;
  private final OAuth2SuccessHandler oAuth2SuccessHandler;
  private final OAuth2FailureHandler oAuth2FailureHandler;

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http.csrf(AbstractHttpConfigurer::disable)
        .cors(AbstractHttpConfigurer::disable)
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .addFilterBefore(headerAuthFilter, UsernamePasswordAuthenticationFilter.class)
        .authorizeHttpRequests(
            auth -> auth.requestMatchers(PUBLIC_ENDPOINTS).permitAll().anyRequest().authenticated())
        .oauth2Login(
            oauth2 ->
                oauth2
                    .userInfoEndpoint(userInfo -> userInfo.userService(oauth2UserService()))
                    .successHandler(oAuth2SuccessHandler)
                    .failureHandler(oAuth2FailureHandler))
        .exceptionHandling(
            ex ->
                ex.authenticationEntryPoint(
                        ((request, response, authException) -> {
                          response.setContentType("application/json");
                          response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                          response.getWriter().write("{\"error\":\"Authentication required\"}");
                        }))
                    .accessDeniedHandler(
                        (request, response, accessDeniedException) -> {
                          response.setContentType("application/json");
                          response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                          response.getWriter().write("{\"error\":\"Access denied\"}");
                        }))
        .build();
  }

  @Bean
  public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
    DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
    return userRequest -> {
      OAuth2User user = delegate.loadUser(userRequest);
      Set<GrantedAuthority> authorities = new HashSet<>();

      String email = user.getAttribute("email");
      if (email != null) {
        authorities.add(new SimpleGrantedAuthority("ROLE_CUSTOMER"));
      }

      return new DefaultOAuth2User(authorities, user.getAttributes(), "email");
    };
  }

  @Bean
  public WebSecurityCustomizer ignoreResources() {
    return webSecurity ->
        webSecurity
            .ignoring()
            .requestMatchers(
                "/actuator/**",
                "/v3/**",
                "/webjars/**",
                "/swagger-ui*/*swagger-initializer.js",
                "/swagger-ui*/**",
                "/favicon.ico");
  }
}
