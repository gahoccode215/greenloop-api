package com.greenloop.gateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import java.util.List;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JwtUtil {

  private final RedisTemplate<String, String> redisTemplate;

  private final String CLAIM_USER_ID = "userId";
  private final String CLAIM_ROLES = "roles";
  private final String JTI = "jti";
  private final String REDIS_BLACKLIST_PREFIX = "bl:";

  @Value("${spring.security.jwt.secret}")
  private String secret;

  public JwtUtil(RedisTemplate<String, String> redisTemplate) {
    this.redisTemplate = redisTemplate;
  }

  private SecretKey getSigningKey() {
    return Keys.hmacShaKeyFor(secret.getBytes());
  }

  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  public String extractUserId(String token) {
    return extractClaim(token, claims -> claims.get(CLAIM_USER_ID, String.class));
  }

  public List<String> extractRoles(String token) {
    Object roles = extractClaim(token, claims -> claims.get(CLAIM_ROLES));
    if (roles instanceof List<?>) {
      return ((List<?>) roles).stream().map(Object::toString).toList();
    }
    return List.of();
  }

  public <T> T extractClaim(String token, java.util.function.Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  private boolean isBlacklisted(String jti) {
    if (jti == null) return false;
    String key = REDIS_BLACKLIST_PREFIX + jti;

    try {
      //      long startTime = System.nanoTime();
      //      boolean result = redisTemplate.hasKey(key);
      //      long endTime = System.nanoTime();
      //
      //      long latencyMs = (endTime - startTime) / 1_000_000;
      //
      //      log.info("[RedisLatency] hasKey('{}') took {} ms", key, latencyMs);

      return redisTemplate.hasKey(key);
    } catch (Exception e) {
      log.error("[RedisLatency] Error checking key '{}': {}", key, e.getMessage());
      return false;
    }
  }

  private Claims extractAllClaims(String token) {
    try {
      return Jwts.parser()
          .verifyWith(getSigningKey())
          .build()
          .parseSignedClaims(token)
          .getPayload();
    } catch (JwtException e) {
      log.error("Invalid JWT token: {}", e.getMessage());
      throw e;
    }
  }

  public boolean isTokenExpired(String token) {
    return extractClaim(token, Claims::getExpiration).before(new Date());
  }

  public boolean validateToken(String token) {
    try {
      Claims claims = extractAllClaims(token);
      String jti = claims.get(JTI, String.class);

      return !isTokenExpired(token) && !isBlacklisted(jti);
    } catch (JwtException | IllegalArgumentException e) {
      log.error("Token validation failed: {}", e.getMessage());
      return false;
    }
  }
}
