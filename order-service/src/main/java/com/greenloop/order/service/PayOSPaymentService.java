package com.greenloop.order.service;


import com.greenloop.order.dto.response.PayOSPaymentResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import vn.payos.PayOS;
import vn.payos.model.v2.paymentRequests.CreatePaymentLinkRequest;
import vn.payos.model.v2.paymentRequests.CreatePaymentLinkResponse;

import java.math.BigDecimal;

@Service
@RequiredArgsConstructor
@Slf4j
public class PayOSPaymentService {

    private final PayOS payOS;

    @Value("${payos.return-url}")
    private String returnUrl;

    @Value("${payos.cancel-url}")
    private String cancelUrl;

    public PayOSPaymentResponse createPaymentUrl(String orderId, BigDecimal amount) {
        try {
            // Tạo orderCode unique
            long orderCode = System.currentTimeMillis() / 1000;

            log.info("Creating PayOS payment link - OrderId: {}, OrderCode: {}", orderId, orderCode);

            CreatePaymentLinkRequest paymentData = CreatePaymentLinkRequest.builder()
                    .orderCode(orderCode)
                    .amount(amount.longValue())
                    .description("DH " + orderId.substring(0, Math.min(8, orderId.length())))
                    .returnUrl(returnUrl)
                    .cancelUrl(cancelUrl)
                    .build();

            CreatePaymentLinkResponse data = payOS.paymentRequests().create(paymentData);

            log.info("PayOS payment link created - OrderCode: {}, URL: {}", orderCode, data.getCheckoutUrl());

            // Trả về cả URL và orderCode để OrderService lưu
            return PayOSPaymentResponse.builder()
                    .checkoutUrl(data.getCheckoutUrl())
                    .paymentOrderCode(orderCode)
                    .build();

        } catch (Exception e) {
            log.error("Error creating PayOS payment link for orderId {}: {}", orderId, e.getMessage());
            throw new RuntimeException("Không thể tạo link thanh toán: " + e.getMessage());
        }
    }
}

