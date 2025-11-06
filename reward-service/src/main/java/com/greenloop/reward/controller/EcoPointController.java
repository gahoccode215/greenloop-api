package com.greenloop.reward.controller;

import com.greenloop.reward.dto.request.EcoPointRuleFilterRequest;
import com.greenloop.reward.dto.request.EcoPointRuleRequest;
import com.greenloop.reward.dto.response.ApiResponseDTO;
import com.greenloop.reward.dto.response.EcoPointResponse;
import com.greenloop.reward.enums.EcoActionType;
import com.greenloop.reward.service.EcoPointRuleService;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/eco-points")
@RequiredArgsConstructor
@Slf4j
public class EcoPointController {
  private final EcoPointRuleService ecoPointRuleService;

  @PostMapping
  @Operation(
      summary = "Create eco points based on defined rules",
      description =
          "This endpoint triggers the creation of eco points according to predefined rules.")
  @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
  public ResponseEntity<ApiResponseDTO<Long>> createEcoPoints(
      @RequestBody @Valid EcoPointRuleRequest request) {
    return ResponseEntity.ok(
        ApiResponseDTO.<Long>builder()
            .data(ecoPointRuleService.createEcoPointRules(request))
            .message("Event created successfully")
            .statusCode(HttpStatus.OK.value())
            .success(true)
            .build());
  }

  @GetMapping
  @Operation(
      summary = "Get all eco point rules",
      description = "Filter by action type, code, name, or category ID.")
  public ResponseEntity<ApiResponseDTO<List<EcoPointResponse>>> getAllEcoPointRules(
      @RequestParam(required = false) EcoActionType actionType,
      @RequestParam(required = false) String code,
      @RequestParam(required = false) String name,
      @RequestParam(required = false) Long categoryId) {

    EcoPointRuleFilterRequest filter =
        EcoPointRuleFilterRequest.builder()
            .actionType(actionType)
            .code(code)
            .name(name)
            .categoryId(categoryId)
            .build();

    List<EcoPointResponse> rules = ecoPointRuleService.getAllEcoPointRules(filter);

    return ResponseEntity.ok(
        ApiResponseDTO.<List<EcoPointResponse>>builder()
            .data(rules)
            .message("Fetched eco point rules successfully")
            .statusCode(HttpStatus.OK.value())
            .success(true)
            .build());
  }

  @PutMapping("/{id}")
  @Operation(summary = "Update eco point rule", description = "Update rule details by ID.")
  @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
  public ResponseEntity<ApiResponseDTO<Void>> updateEcoPointRule(
      @PathVariable Long id, @RequestBody @Valid EcoPointRuleRequest request) {
    ecoPointRuleService.updateEcoPointRule(id, request);
    return ResponseEntity.ok(
        ApiResponseDTO.<Void>builder()
            .message("Eco point rule updated successfully")
            .statusCode(HttpStatus.OK.value())
            .success(true)
            .build());
  }

  @PutMapping("/{id}/status")
  @Operation(summary = "Change rule status", description = "Activate or deactivate eco point rule.")
  @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
  public ResponseEntity<ApiResponseDTO<Void>> changeStatus(@PathVariable Long id) {
    ecoPointRuleService.changeStatus(id);
    return ResponseEntity.ok(
        ApiResponseDTO.<Void>builder()
            .message("Eco point rule status changed successfully")
            .statusCode(HttpStatus.OK.value())
            .success(true)
            .build());
  }
}
