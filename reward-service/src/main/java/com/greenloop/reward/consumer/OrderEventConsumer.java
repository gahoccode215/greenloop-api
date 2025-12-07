package com.greenloop.reward.consumer;

import com.greenloop.reward.dto.event.OrderOfflineCreatedEvent;
import com.greenloop.reward.dto.request.RedeemVoucherRequest;
import com.greenloop.reward.service.EcoPointUserService;
import com.greenloop.reward.service.VoucherService;
import java.util.function.Consumer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class OrderEventConsumer {

  private final EcoPointUserService ecoPointUserService;
  private final VoucherService voucherService;

  @Bean
  public Consumer<OrderOfflineCreatedEvent> orderOfflineCreatedRewardConsumer() {
    return event -> {
      log.info(
          "Received OrderOfflineCreatedEvent - orderId: {}, customerId: {}, earnedEcoPoints: {}, voucherUserId: {}",
          event.getOrderId(),
          event.getCustomerId(),
          event.getEarnedEcoPoints(),
          event.getVoucherUserId());

      // 1. Xử lý Voucher nếu có sử dụng
      processVoucherRedemption(event);

      // 2. Cộng EcoPoints cho customer (không phải guest)
      processEcoPoints(event);
    };
  }

  private void processVoucherRedemption(OrderOfflineCreatedEvent event) {
    if (event.getVoucherUserId() == null) {
      log.info("No voucher used for orderId: {}", event.getOrderId());
      return;
    }

    try {
      RedeemVoucherRequest redeemRequest =
          RedeemVoucherRequest.builder()
              .voucherUserId(event.getVoucherUserId())
              .orderId((long) Math.abs(event.getOrderId().hashCode()))
              .discountValue(event.getDiscountAmount())
              .build();

      voucherService.redeemVoucher(redeemRequest);
      log.info(
          "Voucher redemption processed for voucherUserId: {}, orderId: {}",
          event.getVoucherUserId(),
          event.getOrderId());

    } catch (Exception e) {
      log.error(
          "Failed to process voucher redemption for orderId {}: {}",
          event.getOrderId(),
          e.getMessage(),
          e);
    }
  }

  private void processEcoPoints(OrderOfflineCreatedEvent event) {
    if (Boolean.TRUE.equals(event.getIsGuestPurchase())) {
      log.info("Skipping eco points for guest purchase - orderId: {}", event.getOrderId());
      return;
    }

    if (event.getEarnedEcoPoints() == null || event.getEarnedEcoPoints() <= 0) {
      log.info("No eco points to add for orderId: {}", event.getOrderId());
      return;
    }

    try {
      ecoPointUserService.addEcoPointsForOfflineOrder(
          event.getCustomerId(),
          event.getEarnedEcoPoints(),
          event.getOrderId(),
          event.getOrderCode());
      log.info(
          "Added {} eco points for customer {} - orderId: {}",
          event.getEarnedEcoPoints(),
          event.getCustomerId(),
          event.getOrderId());

    } catch (Exception e) {
      log.error("Failed to add eco points for order {}: {}", event.getOrderId(), e.getMessage(), e);
    }
  }
}
