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

    @Value("${payos.return-url-mobile}")
    private String returnUrlMobile;

    @Value("${payos.return-url-web}")
    private String returnUrlWeb;

    @Value("${payos.cancel-url-web}")
    private String cancelUrlWeb;

    @Value("${payos.cancel-url-mobile}")
    private String cancelUrlMobile;

    public PayOSPaymentResponse createPaymentUrl(String orderId, BigDecimal amount, String platform, Boolean isOrderOffline) {
        try {
            long orderCode = System.currentTimeMillis() / 1000;
            String returnUrl = getReturnUrl(platform);
            String cancelUrl = getCancelUrl(platform);
            log.info("RETURN URL:{}", returnUrl);
            log.info("CANCEL URL:{}", cancelUrl);
            if (isOrderOffline) {
                returnUrl = "https://green-loop-web-fe-g6pj.vercel.app/admin/orders/";
                cancelUrl = "https://green-loop-web-fe-g6pj.vercel.app/admin/orders/";
            }
            CreatePaymentLinkRequest paymentData = CreatePaymentLinkRequest.builder()
                    .orderCode(orderCode)
                    .amount(amount.longValue())
                    .description("DH " + orderId.substring(0, Math.min(8, orderId.length())))
                    .returnUrl(returnUrl)
                    .cancelUrl(cancelUrl)
                    .build();

            CreatePaymentLinkResponse data = payOS.paymentRequests().create(paymentData);


            return PayOSPaymentResponse.builder()
                    .checkoutUrl(data.getCheckoutUrl())
                    .paymentOrderCode(orderCode)
                    .build();

        } catch (Exception e) {
            throw new RuntimeException("Không thể tạo link thanh toán: " + e.getMessage());
        }
    }

    private String getReturnUrl(String platform) {
        if ("web".equalsIgnoreCase(platform)) {
            return returnUrlWeb;
        }
        return returnUrlMobile;
    }

    private String getCancelUrl(String platform) {
        if ("web".equalsIgnoreCase(platform)) {
            return cancelUrlWeb;
        }
        return cancelUrlMobile;
    }
}
