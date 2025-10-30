package com.greenloop.user.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class OAuth2FailureHandler extends SimpleUrlAuthenticationFailureHandler {

  @Value("${app.oauth2.frontend-redirect-url:http://localhost:5173/auth/callback}")
  private String frontendRedirectUrl;

  @Override
  public void onAuthenticationFailure(
      HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
      throws IOException, ServletException {

    log.error("OAuth2 authentication failed: {}", exception.getMessage());

    String errorMessage = URLEncoder.encode(exception.getMessage(), StandardCharsets.UTF_8);
    String redirectUrl = frontendRedirectUrl + "?error=" + errorMessage;

    getRedirectStrategy().sendRedirect(request, response, redirectUrl);
  }
}
