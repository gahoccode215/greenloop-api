package com.greenloop.reward.controller;

import com.greenloop.reward.dto.request.VoucherUsedRequest;
import com.greenloop.reward.dto.response.ApiResponseDTO;
import com.greenloop.reward.service.VoucherInternalService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/internal/vouchers")
@RequiredArgsConstructor
@Slf4j
public class VoucherInternalController {

  private final VoucherInternalService voucherInternalService;

  @PostMapping("/mark-used")
  public ResponseEntity<ApiResponseDTO<Void>> markVoucherAsUsed(
      @RequestBody VoucherUsedRequest request) {

    log.info(
        "Internal API: Mark voucher as used - orderId: {}, voucherUserId: {}",
        request.getOrderId(),
        request.getVoucherUserId());

    voucherInternalService.markVoucherAsUsed(request);

    return ResponseEntity.ok(
        ApiResponseDTO.success(
            "Voucher đã được đánh dấu là đã sử dụng thành công", null, HttpStatus.OK));
  }
}
