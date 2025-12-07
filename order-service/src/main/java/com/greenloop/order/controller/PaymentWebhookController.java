package com.greenloop.order.controller;

import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.service.OrderOfflineService;
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
    private final OrderOfflineService orderOfflineService;

    @PostMapping("/payos-webhook")
    public ResponseEntity<ApiResponseDTO<WebhookData>> handlePayOSWebhook(
            @RequestBody Webhook webhookBody,
            HttpServletRequest request) {
        try {
            // 1. Verify webhook signature từ PayOS
            WebhookData webhookData = payOS.webhooks().verify(webhookBody);

            log.info("Received PayOS webhook - OrderCode: {}, Code: {}, Reference: {}",
                    webhookData.getOrderCode(),
                    webhookData.getCode(),
                    webhookData.getReference());

            // 2. Tìm orderId từ paymentOrderCode
            String orderId = orderService.findOrderIdByPaymentOrderCode(webhookData.getOrderCode());

            if (orderId == null) {
                log.error("Order not found for paymentOrderCode: {}", webhookData.getOrderCode());
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                        ApiResponseDTO.error(
                                "Không tìm thấy đơn hàng với orderCode: " + webhookData.getOrderCode(),
                                HttpStatus.NOT_FOUND,
                                request.getRequestURI()
                        )
                );
            }

            // 3. Lấy thông tin đơn hàng để phân loại
            Order order = orderService.getOrderEntityById(orderId);

            // 4. Xử lý theo kết quả thanh toán
            if ("00".equals(webhookData.getCode())) {
                // Thanh toán thành công
                handleSuccessfulPayment(order, webhookData);

                return ResponseEntity.ok(
                        ApiResponseDTO.success(
                                "Thanh toán thành công cho đơn hàng " + order.getOrderCode(),
                                webhookData,
                                HttpStatus.OK
                        )
                );
            } else {
                // Thanh toán thất bại
                handleFailedPayment(order, webhookData);

                return ResponseEntity.ok(
                        ApiResponseDTO.success(
                                "Webhook nhận được nhưng thanh toán không thành công - Code: " + webhookData.getCode(),
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

    /**
     * Xử lý thanh toán thành công
     * Phân biệt giữa Online và Offline orders
     */
    private void handleSuccessfulPayment(Order order, WebhookData webhookData) {
        String orderId = order.getOrderId();
        OrderType orderType = order.getOrderType();
        PaymentMethod paymentMethod = order.getPaymentMethod();

        // Cập nhật payment status và transaction ID
        orderService.updatePaymentStatus(orderId, PaymentStatus.PAID);
        orderService.updatePaymentTransactionId(orderId, webhookData.getReference());

        log.info("Processing successful payment for Order: {}, Type: {}, PaymentMethod: {}",
                order.getOrderCode(), orderType, paymentMethod);

        // Xử lý theo loại đơn hàng
        if (OrderType.OFFLINE.equals(orderType)) {
            handleOfflineOrderPayment(order);
        } else {
            handleOnlineOrderPayment(order);
        }
    }

    /**
     * Xử lý thanh toán thành công cho đơn OFFLINE
     */
    private void handleOfflineOrderPayment(Order order) {
        String orderId = order.getOrderId();

        // Cập nhật trạng thái đơn hàng thành COMPLETED
        orderService.updateOrderStatus(orderId, OrderStatus.COMPLETED);

        // Publish event để:
        // - Chuyển sản phẩm RESERVED → SOLD
        // - Cộng eco points cho customer
        // - Mark voucher as used
        orderOfflineService.publishOrderOfflineCreatedEventDelayed(order);

        log.info("Offline order {} completed after PayOS payment. Event published.",
                order.getOrderCode());
    }

    /**
     * Xử lý thanh toán thành công cho đơn ONLINE
     */
    private void handleOnlineOrderPayment(Order order) {
        String orderId = order.getOrderId();
        OrderStatus currentStatus = order.getOrderStatus();

        // Chỉ cập nhật nếu đang ở trạng thái PENDING
        if (OrderStatus.PENDING.equals(currentStatus)) {
            // Đơn online sau khi thanh toán vẫn giữ PENDING
            // Đợi admin CONFIRM để chuyển sang PROCESSING
            orderService.updateOrderStatus(orderId, OrderStatus.PENDING);

            log.info("Online order {} payment confirmed. Status remains PENDING, waiting for admin confirmation.",
                    order.getOrderCode());
        } else {
            log.warn("Online order {} already in status {}. Skipping status update.",
                    order.getOrderCode(), currentStatus);
        }
    }

    /**
     * Xử lý thanh toán thất bại
     */
    private void handleFailedPayment(Order order, WebhookData webhookData) {
        String orderId = order.getOrderId();

        // Cập nhật payment status
        orderService.updatePaymentStatus(orderId, PaymentStatus.FAILED);

        log.warn("Payment failed for order {} - Code: {}, Desc: {}",
                order.getOrderCode(),
                webhookData.getCode(),
                webhookData.getDesc());

        // TODO: Có thể gửi notification cho customer/admin
        // TODO: Nếu là OFFLINE, có thể tự động cancel order sau X phút
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
