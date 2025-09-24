package com.greeloop.user.util;

import com.greeloop.user.constant.JwtConstants;
import com.greeloop.user.entity.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Component
@Slf4j
public class JwtUtil {

    private final RedisTemplate<String, String> redisTemplate;

    @Value("${spring.security.jwt.secret}")
    private String secret;

    @Value("${spring.security.jwt.expiration}")
    private Long expiration;

    @Value("${spring.security.jwt.refresh-expiration}")
    private Long refreshExpiration;

    public JwtUtil(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtConstants.CLAIM_USER_ID, user.getId().toString());
        claims.put(JwtConstants.CLAIM_EMAIL, user.getEmail());
        claims.put(JwtConstants.CLAIM_FIRST_NAME, user.getFirstName());
        claims.put(JwtConstants.CLAIM_LAST_NAME, user.getLastName());
        claims.put(JwtConstants.CLAIM_ROLE, user.getRole().getName());
        claims.put(JwtConstants.CLAIM_JTI, UUID.randomUUID().toString());
        claims.put(JwtConstants.CLAIM_TYPE, JwtConstants.TOKEN_TYPE_ACCESS);

        return createToken(claims, user.getEmail(), expiration);
    }

    public String generateRefreshToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtConstants.CLAIM_USER_ID, user.getId().toString());
        claims.put(JwtConstants.CLAIM_EMAIL, user.getEmail());
        claims.put(JwtConstants.CLAIM_TYPE, JwtConstants.TOKEN_TYPE_REFRESH);
        claims.put(JwtConstants.CLAIM_JTI, UUID.randomUUID().toString());

        return createToken(claims, user.getEmail(), refreshExpiration);
    }


    public boolean validateToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            String jti = claims.get(JwtConstants.CLAIM_JTI, String.class);

            return !isTokenExpired(token) && !isBlacklisted(jti);
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public void blacklistToken(String token) {
        try {
            String jti = extractClaim(token, claims -> claims.get(JwtConstants.CLAIM_JTI, String.class));
            Date expiration = extractClaim(token, Claims::getExpiration);
            long ttl = expiration.getTime() - System.currentTimeMillis();

            if (ttl > 0) {
                redisTemplate.opsForValue().set(
                        JwtConstants.REDIS_BLACKLIST_PREFIX + jti,
                        "1",
                        Duration.ofMillis(ttl)
                );
            }
        } catch (Exception e) {
            log.error("Failed to blacklist token: {}", e.getMessage());
        }
    }

    private boolean isBlacklisted(String jti) {
        if (jti == null) return false;
        try {
            return redisTemplate.hasKey(JwtConstants.REDIS_BLACKLIST_PREFIX + jti);
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Long getExpirationTime() {
        return expiration;
    }

    public Long getRefreshExpirationTime() {
        return refreshExpiration;
    }

    public String getJti(String token) {
        return extractClaim(token, claims -> claims.get(JwtConstants.CLAIM_JTI, String.class));
    }

    public boolean isRefreshToken(String token) {
        try {
            String tokenType = extractClaim(token, claims -> claims.get(JwtConstants.CLAIM_TYPE, String.class));
            return JwtConstants.TOKEN_TYPE_REFRESH.equals(tokenType);
        } catch (Exception e) {
            return false;
        }
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
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

    private String createToken(Map<String, Object> claims, String subject, Long tokenExpiration) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + tokenExpiration);

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }
}
