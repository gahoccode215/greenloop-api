package com.greenloop.order.controller;

import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.service.PaymentWebhookService;
import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import vn.payos.PayOS;
import vn.payos.model.webhooks.ConfirmWebhookResponse;
import vn.payos.model.webhooks.Webhook;
import vn.payos.model.webhooks.WebhookData;

@RestController
@RequestMapping("/api/v1/orders/payment")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Payment Webhook Controller", description = "Controller xử lý webhook thanh toán từ PayOS")
@Hidden
public class PaymentWebhookController {

    private final PayOS payOS;
    private final PaymentWebhookService paymentWebhookService;

    @PostMapping("/payos-webhook")
    public ResponseEntity<ApiResponseDTO<WebhookData>> handlePayOSWebhook(
            @RequestBody Webhook webhookBody,
            HttpServletRequest request) {
        try {
            // 1. Verify webhook signature từ PayOS
            WebhookData webhookData = payOS.webhooks().verify(webhookBody);

            log.info("Received PayOS webhook - PaymentOrderCode: {}, Code: {}, Reference: {}",
                    webhookData.getOrderCode(),
                    webhookData.getCode(),
                    webhookData.getDesc());

            // 2. Test webhook từ PayOS
            if (webhookData.getOrderCode() == 123L) {
                log.info("Received PayOS test webhook. Returning success response.");
                return ResponseEntity.ok(
                        ApiResponseDTO.success(
                                "Webhook test nhận thành công",
                                webhookData,
                                HttpStatus.OK
                        )
                );
            }

            // 3. Delegate sang Service xử lý
            String message = paymentWebhookService.processPayOSWebhook(webhookData);

            return ResponseEntity.ok(
                    ApiResponseDTO.success(
                            message,
                            webhookData,
                            HttpStatus.OK
                    )
            );

        } catch (Exception e) {
            log.error("Error processing PayOS webhook: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    ApiResponseDTO.error(
                            "Lỗi xử lý webhook: " + e.getMessage(),
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            request.getRequestURI()
                    )
            );
        }
    }

    @PostMapping("/confirm-webhook")
    public ResponseEntity<ApiResponseDTO<ConfirmWebhookResponse>> confirmWebhook(
            @RequestParam String webhookUrl,
            HttpServletRequest request) {
        try {
            ConfirmWebhookResponse result = payOS.webhooks().confirm(webhookUrl);
            return ResponseEntity.ok(
                    ApiResponseDTO.success(
                            "Webhook xác thực thành công",
                            result,
                            HttpStatus.OK
                    )
            );
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    ApiResponseDTO.error(
                            "Lỗi xác thực webhook: " + e.getMessage(),
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            request.getRequestURI()
                    )
            );
        }
    }
}
