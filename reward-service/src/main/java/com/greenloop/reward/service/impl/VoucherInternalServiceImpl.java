package com.greenloop.reward.service.impl;

import com.greenloop.reward.dto.request.VoucherUsedRequest;
import com.greenloop.reward.entity.VoucherRedemption;
import com.greenloop.reward.entity.VoucherUser;
import com.greenloop.reward.enums.ErrorCode;
import com.greenloop.reward.enums.VoucherUserStatus;
import com.greenloop.reward.exception.BusinessException;
import com.greenloop.reward.repository.VoucherRedemptionRepository;
import com.greenloop.reward.repository.VoucherUserRepository;
import com.greenloop.reward.service.VoucherInternalService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class VoucherInternalServiceImpl implements VoucherInternalService {

  private final VoucherUserRepository voucherUserRepository;
  private final VoucherRedemptionRepository voucherRedemptionRepository;

  @Override
  @Transactional
  public void markVoucherAsUsed(VoucherUsedRequest request) {
    log.info(
        "Processing voucher usage from Order Service - orderId: {}, voucherUserId: {}",
        request.getOrderId(),
        request.getVoucherUserId());

    // 1. Tìm VoucherUser
    VoucherUser voucherUser =
        voucherUserRepository
            .findById(request.getVoucherUserId())
            .orElseThrow(
                () -> {
                  log.error("VoucherUser not found with ID: {}", request.getVoucherUserId());
                  return new BusinessException(ErrorCode.VOUCHER_USER_NOT_FOUND);
                });

    // 2. Validate status
    if (voucherUser.getStatus() != VoucherUserStatus.AVAILABLE) {
      log.warn(
          "VoucherUser {} is not AVAILABLE, current status: {}",
          request.getVoucherUserId(),
          voucherUser.getStatus());
      throw new BusinessException(ErrorCode.VOUCHER_USER_NOT_AVAILABLE);
    }

    // 3. Validate quantity
    if (voucherUser.getQuantity() == null || voucherUser.getQuantity() <= 0) {
      log.error("VoucherUser {} has no quantity left", request.getVoucherUserId());
      throw new BusinessException(ErrorCode.VOUCHER_USER_OUT_OF_QUANTITY);
    }

    // 4. Trừ quantity
    int newQuantity = voucherUser.getQuantity() - 1;
    voucherUser.setQuantity(newQuantity);
    voucherUser.setRedeemedAt(request.getUsedAt());

    // 5. Nếu quantity = 0 → đổi status thành USED
    if (newQuantity == 0) {
      voucherUser.setStatus(VoucherUserStatus.REDEEMED);
      log.info("VoucherUser {} status changed to USED", request.getVoucherUserId());
    }

    // 6. Tạo VoucherRedemption history
    VoucherRedemption redemption =
        VoucherRedemption.builder()
            .voucherUser(voucherUser)
            .orderId((long) Math.abs(request.getOrderId().hashCode())) // Convert String to Long
            .discountValue(request.getDiscountValue())
            .redeemedAt(request.getUsedAt())
            .build();

    voucherRedemptionRepository.save(redemption);
    voucherUserRepository.save(voucherUser);

    log.info(
        "Voucher marked as used successfully. VoucherUserId: {}, OrderId: {}, Remaining quantity: {}",
        request.getVoucherUserId(),
        request.getOrderId(),
        newQuantity);
  }
}
