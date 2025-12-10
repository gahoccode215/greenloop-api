package com.greenloop.reward.consumer;

import com.greenloop.reward.dto.event.VoucherUsedEvent;
import com.greenloop.reward.dto.request.RedeemVoucherRequest;
import com.greenloop.reward.service.VoucherService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Service;

import java.util.function.Consumer;

@Slf4j
@Service
@RequiredArgsConstructor
public class VoucherUsedConsumer {

    private final VoucherService voucherService;

    @Bean
    public Consumer<VoucherUsedEvent> orderCheckoutVoucherUsedConsumer() {
        return event -> {
            log.info(
                    "Received VoucherUsedEvent - orderId: {}, voucherUserId: {}, discountValue: {}",
                    event.getOrderId(),
                    event.getVoucherUserId(),
                    event.getDiscountValue());

            processVoucherRedemption(event);
        };
    }

    private void processVoucherRedemption(VoucherUsedEvent event) {
        if (event.getVoucherUserId() == null) {
            log.info("No voucher used for orderId: {}", event.getOrderId());
            return;
        }

        try {
            RedeemVoucherRequest request = RedeemVoucherRequest.builder()
                    .voucherUserId(event.getVoucherUserId())
                    .orderId((long) Math.abs(event.getOrderId().hashCode()))
                    .discountValue(event.getDiscountValue())
                    .build();

            voucherService.redeemVoucher(request);

            log.info(
                    "Voucher redemption processed successfully for voucherUserId: {}, orderId: {}",
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
}
