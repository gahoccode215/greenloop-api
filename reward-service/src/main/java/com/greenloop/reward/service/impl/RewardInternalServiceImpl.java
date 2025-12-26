package com.greenloop.reward.service.impl;

import com.greenloop.reward.dto.event.EcoPointTransactionDTO;
import com.greenloop.reward.dto.request.VoucherUsedRequest;
import com.greenloop.reward.entity.VoucherRedemption;
import com.greenloop.reward.entity.VoucherUser;
import com.greenloop.reward.enums.EcoPointType;
import com.greenloop.reward.enums.ErrorCode;
import com.greenloop.reward.enums.SourceType;
import com.greenloop.reward.enums.VoucherUserStatus;
import com.greenloop.reward.exception.BusinessException;
import com.greenloop.reward.repository.VoucherRedemptionRepository;
import com.greenloop.reward.repository.VoucherUserRepository;
import com.greenloop.reward.service.EcoPointUserService;
import com.greenloop.reward.service.RewardInternalService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class RewardInternalServiceImpl implements RewardInternalService {
  private final VoucherUserRepository voucherUserRepository;
  private final VoucherRedemptionRepository voucherRedemptionRepository;
  private final EcoPointUserService ecoPointUserService;

  @Override
  @Transactional
  public void markVoucherAsUsed(VoucherUsedRequest request) {
    VoucherUser voucherUser =
        voucherUserRepository
            .findById(request.getVoucherUserId())
            .orElseThrow(() -> new BusinessException(ErrorCode.VOUCHER_USER_NOT_FOUND));
    if (voucherUser.getStatus() != VoucherUserStatus.AVAILABLE) {
      throw new BusinessException(ErrorCode.VOUCHER_USER_NOT_AVAILABLE);
    }
    if (voucherUser.getQuantity() == null || voucherUser.getQuantity() <= 0) {
      throw new BusinessException(ErrorCode.VOUCHER_USER_OUT_OF_QUANTITY);
    }
    int newQuantity = voucherUser.getQuantity() - 1;
    voucherUser.setQuantity(newQuantity);
    voucherUser.setRedeemedAt(request.getUsedAt());
    if (newQuantity == 0) {
      voucherUser.setStatus(VoucherUserStatus.REDEEMED);
    }
    VoucherRedemption redemption =
        VoucherRedemption.builder()
            .voucherUser(voucherUser)
            .orderId((long) Math.abs(request.getOrderId().hashCode()))
            .discountValue(request.getDiscountValue())
            .redeemedAt(request.getUsedAt())
            .build();
    voucherRedemptionRepository.save(redemption);
    voucherUserRepository.save(voucherUser);
  }

  @Override
  public void addEcoPointsForOnlineOrder(
      Long customerId, Integer points, String orderId, String orderCode) {
    EcoPointTransactionDTO transactionDTO =
        EcoPointTransactionDTO.builder()
            .userId(customerId)
            .points(points)
            .type(EcoPointType.EARNED)
            .sourceType(SourceType.ORDER)
            .sourceId((long) Math.abs(orderId.hashCode()))
            .description("Hoàn thành đơn hàng online - " + orderCode)
            .build();
    ecoPointUserService.updateEcoPointUserBalance(transactionDTO);
  }
}
