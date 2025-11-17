package com.greenloop.reward.controller;

import com.greenloop.reward.dto.response.ApiResponseDTO;
import com.greenloop.reward.dto.response.EcoPointUserResponse;
import com.greenloop.reward.service.EcoPointUserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/eco-point-users")
@RequiredArgsConstructor
@Slf4j
public class EcoPointUserController {
  private final EcoPointUserService ecoPointUserService;

  @GetMapping("/my-eco-points")
  @Operation(
      summary = "Get current user's eco point balance",
      description = "Retrieve the eco point balance for the authenticated user.")
  @Tag(name = "Eco Point User Management")
  @PreAuthorize("isAuthenticated()")
  public ResponseEntity<ApiResponseDTO<EcoPointUserResponse>> getMyEcoPoint() {
    Long userId =
        Long.valueOf(
            SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
    log.info("Fetching eco point balance for user ID: {}", userId);
    EcoPointUserResponse ecoPointUserResponse = ecoPointUserService.getEcoPointOfUser(userId);
    return ResponseEntity.ok(
        ApiResponseDTO.<EcoPointUserResponse>builder()
            .data(ecoPointUserResponse)
            .message("Fetched current user's eco point balance successfully")
            .statusCode(200)
            .success(true)
            .build());
  }

  @GetMapping("/{userId}")
  @Operation(
      summary = "Get eco point balance by user ID",
      description = "Retrieve the eco point balance for a specific user by their user ID.")
  @Tag(name = "Eco Point User Management")
  @PreAuthorize(
      "hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER') or hasRole('ROLE_STAFF') or hasRole('ROLE_STORE_MANAGER')")
  public ResponseEntity<ApiResponseDTO<EcoPointUserResponse>> getEcoPointByUserId(
      @PathVariable Long userId) {
    log.info("Fetching eco point balance for user ID: {}", userId);
    EcoPointUserResponse ecoPointUserResponse = ecoPointUserService.getEcoPointOfUser(userId);
    return ResponseEntity.ok(
        ApiResponseDTO.<EcoPointUserResponse>builder()
            .data(ecoPointUserResponse)
            .message("Fetched eco point balance by user ID successfully")
            .statusCode(200)
            .success(true)
            .build());
  }
}
