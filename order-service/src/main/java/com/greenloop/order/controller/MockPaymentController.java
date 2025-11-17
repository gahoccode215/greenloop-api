package com.greenloop.order.controller;

import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.service.OrderService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/orders/mock")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Mock Payment Controller")
public class MockPaymentController {

    private final OrderService orderService;
    private final OrderRepository orderRepository;

    /**
     * Mock thanh toán thành công bằng orderId
     * POST /api/v1/orders/mock/payment-success/{orderId}
     */
    @Operation(summary = "Mock thanh toán thành công bằng orderId")
    @PostMapping("/payment-success/{orderId}")
    public ResponseEntity<ApiResponseDTO<Map<String, Object>>> mockPaymentSuccessByOrderId(
            @PathVariable String orderId,
            HttpServletRequest request) {
        try {
            log.info("[MOCK] Simulating payment success for orderId: {}", orderId);

            Order order = orderRepository.findById(orderId)
                    .orElseThrow(() -> new RuntimeException("Order not found: " + orderId));

            // Update payment status
            orderService.updatePaymentStatus(orderId, PaymentStatus.PAID);
            orderService.updateOrderStatus(orderId, OrderStatus.CONFIRMED);
            orderService.updatePaymentTransactionId(orderId, "MOCK-TXN-" + System.currentTimeMillis());

            log.info("[MOCK] Payment success simulated for order: {}", orderId);

            Map<String, Object> result = Map.of(
                    "orderId", orderId,
                    "orderCode", order.getOrderCode(),
                    "paymentStatus", "PAID",
                    "orderStatus", "CONFIRMED",
                    "message", "Mock payment success"
            );

            return ResponseEntity.ok(
                    ApiResponseDTO.success(
                            "Mock thanh toán thành công",
                            result,
                            HttpStatus.OK
                    )
            );

        } catch (Exception e) {
            log.error("[MOCK] Error simulating payment: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    ApiResponseDTO.error(
                            "Lỗi mock thanh toán: " + e.getMessage(),
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            request.getRequestURI()
                    )
            );
        }
    }

    /**
     * Mock thanh toán thành công bằng orderCode
     * POST /api/v1/orders/mock/payment-success-by-code/{orderCode}
     */
    @Operation(summary = "Mock thanh toán thành công bằng orderCode")
    @PostMapping("/payment-success-by-code/{orderCode}")
    public ResponseEntity<ApiResponseDTO<Map<String, Object>>> mockPaymentSuccessByOrderCode(
            @PathVariable String orderCode,
            HttpServletRequest request) {
        try {
            log.info("[MOCK] Simulating payment success for orderCode: {}", orderCode);

            Order order = orderRepository.findByOrderCode(orderCode)
                    .orElseThrow(() -> new RuntimeException("Order not found with code: " + orderCode));

            String orderId = order.getOrderId();

            orderService.updatePaymentStatus(orderId, PaymentStatus.PAID);
            orderService.updateOrderStatus(orderId, OrderStatus.CONFIRMED);
            orderService.updatePaymentTransactionId(orderId, "MOCK-TXN-" + System.currentTimeMillis());

            log.info("[MOCK] Payment success simulated for order: {}", orderId);

            Map<String, Object> result = Map.of(
                    "orderId", orderId,
                    "orderCode", orderCode,
                    "paymentStatus", "PAID",
                    "orderStatus", "CONFIRMED",
                    "message", "Mock payment success"
            );

            return ResponseEntity.ok(
                    ApiResponseDTO.success(
                            "Mock thanh toán thành công",
                            result,
                            HttpStatus.OK
                    )
            );

        } catch (Exception e) {
            log.error("[MOCK] Error simulating payment: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    ApiResponseDTO.error(
                            "Lỗi mock thanh toán: " + e.getMessage(),
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            request.getRequestURI()
                    )
            );
        }
    }

    /**
     * Mock thanh toán thành công bằng paymentOrderCode
     * POST /api/v1/orders/mock/payment-success-by-payment-code/{paymentOrderCode}
     */
    @PostMapping("/payment-success-by-payment-code/{paymentOrderCode}")
    public ResponseEntity<ApiResponseDTO<Map<String, Object>>> mockPaymentSuccessByPaymentOrderCode(
            @PathVariable Long paymentOrderCode,
            HttpServletRequest request) {
        try {
            log.info("[MOCK] Simulating payment success for paymentOrderCode: {}", paymentOrderCode);

            String orderId = orderService.findOrderIdByPaymentOrderCode(paymentOrderCode);

            if (orderId == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                        ApiResponseDTO.error(
                                "Order not found with paymentOrderCode: " + paymentOrderCode,
                                HttpStatus.NOT_FOUND,
                                request.getRequestURI()
                        )
                );
            }

            Order order = orderRepository.findById(orderId).orElseThrow();

            orderService.updatePaymentStatus(orderId, PaymentStatus.PAID);
            orderService.updateOrderStatus(orderId, OrderStatus.CONFIRMED);
            orderService.updatePaymentTransactionId(orderId, "MOCK-TXN-" + System.currentTimeMillis());

            log.info("[MOCK] Payment success simulated for order: {}", orderId);

            Map<String, Object> result = Map.of(
                    "orderId", orderId,
                    "orderCode", order.getOrderCode(),
                    "paymentOrderCode", paymentOrderCode,
                    "paymentStatus", "PAID",
                    "orderStatus", "CONFIRMED",
                    "message", "Mock payment success"
            );

            return ResponseEntity.ok(
                    ApiResponseDTO.success(
                            "Mock thanh toán thành công",
                            result,
                            HttpStatus.OK
                    )
            );

        } catch (Exception e) {
            log.error("[MOCK] Error simulating payment: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    ApiResponseDTO.error(
                            "Lỗi mock thanh toán: " + e.getMessage(),
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            request.getRequestURI()
                    )
            );
        }
    }

    /**
     * Mock thanh toán thất bại
     * POST /api/v1/orders/mock/payment-failed/{orderId}
     */
    @PostMapping("/payment-failed/{orderId}")
    public ResponseEntity<ApiResponseDTO<Map<String, Object>>> mockPaymentFailed(
            @PathVariable String orderId,
            HttpServletRequest request) {
        try {
            log.info("[MOCK] Simulating payment failed for orderId: {}", orderId);

            Order order = orderRepository.findById(orderId)
                    .orElseThrow(() -> new RuntimeException("Order not found: " + orderId));

            orderService.updatePaymentStatus(orderId, PaymentStatus.FAILED);
            orderService.updateOrderStatus(orderId, OrderStatus.CANCELLED);

            log.info("[MOCK] Payment failed simulated for order: {}", orderId);

            Map<String, Object> result = Map.of(
                    "orderId", orderId,
                    "orderCode", order.getOrderCode(),
                    "paymentStatus", "FAILED",
                    "orderStatus", "CANCELLED",
                    "message", "Mock payment failed"
            );

            return ResponseEntity.ok(
                    ApiResponseDTO.success(
                            "Mock thanh toán thất bại",
                            result,
                            HttpStatus.OK
                    )
            );

        } catch (Exception e) {
            log.error("[MOCK] Error simulating payment failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    ApiResponseDTO.error(
                            "Lỗi mock thanh toán: " + e.getMessage(),
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            request.getRequestURI()
                    )
            );
        }
    }


}
