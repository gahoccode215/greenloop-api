package com.greenloop.event.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class HeaderAuthFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    String userId = request.getHeader("X-User-ID");
    String rolesHeader = request.getHeader("X-User-Roles");

    if (userId != null && rolesHeader != null) {
      List<GrantedAuthority> authorities =
          Arrays.stream(rolesHeader.split(","))
              .map(String::trim)
              .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
              .collect(Collectors.toList());

      UsernamePasswordAuthenticationToken auth =
          new UsernamePasswordAuthenticationToken(userId, null, authorities);

      SecurityContextHolder.getContext().setAuthentication(auth);
    }

    filterChain.doFilter(request, response);
  }
}
