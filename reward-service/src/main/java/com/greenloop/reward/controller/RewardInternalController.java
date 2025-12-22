package com.greenloop.reward.controller;

import com.greenloop.reward.dto.request.AddEcoPointsRequest;
import com.greenloop.reward.dto.request.VoucherUsedRequest;
import com.greenloop.reward.dto.response.ApiResponseDTO;
import com.greenloop.reward.dto.response.EcoPointUserResponse;
import com.greenloop.reward.dto.response.UserVoucherResponse;
import com.greenloop.reward.service.EcoPointUserService;
import com.greenloop.reward.service.RewardInternalService;
import com.greenloop.reward.service.VoucherService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/internal")
@RequiredArgsConstructor
public class RewardInternalController {
  private final EcoPointUserService ecoPointUserService;
  private final VoucherService voucherService;
  private final RewardInternalService rewardInternalService;

  @GetMapping("/eco-point-users/my-eco-points")
  public ResponseEntity<ApiResponseDTO<EcoPointUserResponse>> getMyEcoPoints(
      @RequestParam("userId") Long userId) {
    EcoPointUserResponse response = ecoPointUserService.getEcoPointOfUser(userId);
    return ResponseEntity.ok(ApiResponseDTO.success("Success", response, HttpStatus.OK));
  }

  @PostMapping("/vouchers/validate/{voucherUserId}")
  public ResponseEntity<ApiResponseDTO<UserVoucherResponse>> validateVoucherForUser(
      @PathVariable("voucherUserId") Long voucherUserId) {
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

  @PostMapping("/rewards/eco-points/add")
  public ResponseEntity<ApiResponseDTO<Void>> addEcoPoints(
      @RequestBody AddEcoPointsRequest request) {
    rewardInternalService.addEcoPointsForOnlineOrder(
        request.getCustomerId(),
        request.getEcoPoints(),
        request.getOrderId(),
        request.getOrderCode());
    return ResponseEntity.ok(
        ApiResponseDTO.success("Eco points added successfully", null, HttpStatus.OK));
  }

  @PostMapping("vouchers/mark-used")
  public ResponseEntity<ApiResponseDTO<Void>> markVoucherAsUsed(
      @RequestBody VoucherUsedRequest request) {
    rewardInternalService.markVoucherAsUsed(request);
    return ResponseEntity.ok(
        ApiResponseDTO.success(
            "Voucher đã được đánh dấu là đã sử dụng thành công", null, HttpStatus.OK));
  }
}
