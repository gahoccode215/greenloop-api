package com.greenloop.order.controller;

import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.service.OrderService;
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
@Tag(name = "Payment Webhook Controller", description = "Controller xử lý webhook thanh toán")
@Hidden
public class PaymentWebhookController {

    private final PayOS payOS;
    private final OrderService orderService;

    @PostMapping("/payos-webhook")
    public ResponseEntity<ApiResponseDTO<WebhookData>> handlePayOSWebhook(
            @RequestBody Webhook webhookBody,
            HttpServletRequest request) {
        try {

            WebhookData webhookData = payOS.webhooks().verify(webhookBody);
            if ("00".equals(webhookData.getCode())) {
                String orderId = orderService.findOrderIdByPaymentOrderCode(webhookData.getOrderCode());

                if (orderId != null) {
                    orderService.updatePaymentStatus(orderId, PaymentStatus.PAID);
                    orderService.updateOrderStatus(orderId, OrderStatus.PENDING);

                    orderService.updatePaymentTransactionId(orderId, webhookData.getReference());


                    return ResponseEntity.ok(
                            ApiResponseDTO.success(
                                    "Thanh toán thành công",
                                    webhookData,
                                    HttpStatus.OK
                            )
                    );
                } else {
                    log.error("Order not found for orderCode: {}", webhookData.getOrderCode());
                    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                            ApiResponseDTO.error(
                                    "Không tìm thấy đơn hàng với orderCode: " + webhookData.getOrderCode(),
                                    HttpStatus.NOT_FOUND,
                                    request.getRequestURI()
                            )
                    );
                }
            } else {
                return ResponseEntity.ok(
                        ApiResponseDTO.success(
                                "Webhook nhận được nhưng thanh toán không thành công",
                                webhookData,
                                HttpStatus.OK
                        )
                );
            }

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
