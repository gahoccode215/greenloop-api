package com.greenloop.reward.controller;

import com.greenloop.reward.dto.response.ApiResponseDTO;
import com.greenloop.reward.dto.response.EcoPointUserResponse;
import com.greenloop.reward.dto.response.UserVoucherResponse;
import com.greenloop.reward.service.EcoPointUserService;
import com.greenloop.reward.service.VoucherService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/internal")
@RequiredArgsConstructor
@Slf4j
public class InternalRewardController {

  private final EcoPointUserService ecoPointUserService;
  private final VoucherService voucherService;

  @GetMapping("/eco-point-users/my-eco-points")
  public ResponseEntity<ApiResponseDTO<EcoPointUserResponse>> getMyEcoPoints(
      @RequestParam("userId") Long userId) {

    log.info("Internal API called: getMyEcoPoints for userId={}", userId);

    EcoPointUserResponse response = ecoPointUserService.getEcoPointOfUser(userId);

    return ResponseEntity.ok(ApiResponseDTO.success("Success", response, HttpStatus.OK));
  }

  @PostMapping("/vouchers/validate/{voucherUserId}")
  public ResponseEntity<ApiResponseDTO<UserVoucherResponse>> validateVoucherForUser(
      @PathVariable("voucherUserId") Long voucherUserId) {

    log.info("Internal API called: validateVoucherForUser for voucherUserId={}", voucherUserId);

    UserVoucherResponse voucherResponse = voucherService.validateVoucherUsage(voucherUserId);

    return ResponseEntity.ok(
        ApiResponseDTO.<UserVoucherResponse>builder()
            .data(voucherResponse)
            .success(true)
            .statusCode(HttpStatus.OK.value())
            .message(
                "Voucher validation completed successfully for voucherUserId: " + voucherUserId)
            .build());
  }
}
