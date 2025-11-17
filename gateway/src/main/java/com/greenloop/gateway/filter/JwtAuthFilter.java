package com.greenloop.gateway.filter;

import com.greenloop.gateway.util.JwtUtil;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class JwtAuthFilter extends AbstractGatewayFilterFactory<JwtAuthFilter.Config> {

  private final JwtUtil jwtUtil;
  private static final AntPathMatcher pathMatcher = new AntPathMatcher();

  private static final List<String> PUBLIC_PATHS =
      List.of(
          "/api/v1/auth/login",
          "/api/v1/auth/register",
          "/api/v1/auth/verify-email",
          "/api/v1/auth/refresh",
          "/api/v1/auth/resend-verify-email-otp",
          "/api/v1/auth/resend-reset-password-otp",
          "/api/v1/auth/change-password-first-time",
          "/api/v1/auth/resend-otp",
          "/api/v1/auth/verify-reset-otp",
          "/api/v1/auth/forgot-password",
          "/api/v1/auth/reset-password",
          "/api/v1/auth/oauth2/exchange",
          "/oauth2/authorization/google",
          "/login/oauth2/code/google",
          "/oauth2/",
          "/login/",
          "/v3/api-docs",
          "/swagger-ui",
          "/swagger-ui.html",
          "/webjars/swagger-ui",
          "/api/v1/events/customers/**",
          "/api/v1/eco-points/**",
          "/api/v1/products/**",
          "/api/v1/goship/addresses/**",
          "/api/v1/goship/shipments/**");

  public JwtAuthFilter(JwtUtil jwtUtil) {
    super(Config.class);
    this.jwtUtil = jwtUtil;
  }

  @Override
  public GatewayFilter apply(Config config) {
    return (exchange, chain) -> {
      ServerHttpRequest request = exchange.getRequest();
      String path = request.getURI().getPath();
      String token = extractToken(request);

      if (isPublicPath(path)) {
        if (token != null && jwtUtil.validateToken(token)) {
          try {
            String userId = jwtUtil.extractUserId(token);
            String username = jwtUtil.extractUsername(token);
            List<String> roles = jwtUtil.extractRoles(token);
            String rolesHeader = String.join(",", roles);

            ServerHttpRequest modifiedRequest =
                request
                    .mutate()
                    .header("X-User-ID", userId)
                    .header("X-Username", username)
                    .header("X-User-Roles", rolesHeader)
                    .header("Authorization", "Bearer " + token)
                    .build();

            log.debug("Public API + valid token: {}", username);
            return chain.filter(exchange.mutate().request(modifiedRequest).build());
          } catch (Exception e) {
            log.error("Error processing JWT token", e);
            return chain.filter(exchange);
          }
        }
        return chain.filter(exchange);
      }

      if (token == null) {
        return onError(exchange, "Missing Authorization header", HttpStatus.UNAUTHORIZED);
      }

      if (!jwtUtil.validateToken(token)) {
        return onError(exchange, "Invalid or expired token", HttpStatus.UNAUTHORIZED);
      }

      try {
        String userId = jwtUtil.extractUserId(token);
        String username = jwtUtil.extractUsername(token);

        List<String> roles = jwtUtil.extractRoles(token);
        String rolesHeader = String.join(",", roles);

        ServerHttpRequest modifiedRequest =
            request
                .mutate()
                .header("X-User-ID", userId)
                .header("X-Username", username)
                .header("X-User-Roles", rolesHeader)
                .header("Authorization", "Bearer " + token)
                .build();

        log.debug("JWT validated for user: {} with roles: {}", username, roles);
        return chain.filter(exchange.mutate().request(modifiedRequest).build());

      } catch (Exception e) {
        log.error("Error processing JWT token", e);
        return onError(exchange, "Token processing error", HttpStatus.INTERNAL_SERVER_ERROR);
      }
    };
  }

  private boolean isPublicPath(String path) {
    return PUBLIC_PATHS.stream().anyMatch(pattern -> pathMatcher.match(pattern, path));
  }

  private String extractToken(ServerHttpRequest request) {
    String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
    if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
      return authHeader.substring(7);
    }
    return null;
  }

  private Mono<Void> onError(
      org.springframework.web.server.ServerWebExchange exchange,
      String message,
      HttpStatus status) {
    ServerHttpResponse response = exchange.getResponse();
    response.setStatusCode(status);
    response.getHeaders().add("Content-Type", "application/json");

    String body =
        String.format(
            "{\"success\":false,\"message\":\"%s\",\"statusCode\":%d}", message, status.value());

    org.springframework.core.io.buffer.DataBuffer buffer =
        response.bufferFactory().wrap(body.getBytes());
    return response.writeWith(Mono.just(buffer));
  }

  public static class Config {}
}
