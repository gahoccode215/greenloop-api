package com.greenloop.order.controller;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.constant.ProductStatusConstant;
import com.greenloop.order.dto.event.OrderCheckedOutEvent;
import com.greenloop.order.dto.redis.PendingOrderRedis;
import com.greenloop.order.dto.request.CreateOrderRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.OrderItem;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.service.CartService;
import com.greenloop.order.service.OrderOfflineService;
import com.greenloop.order.service.OrderService;
import com.greenloop.order.service.PendingOrderCacheService;
import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import vn.payos.PayOS;
import vn.payos.model.webhooks.ConfirmWebhookResponse;
import vn.payos.model.webhooks.Webhook;
import vn.payos.model.webhooks.WebhookData;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/v1/orders/payment")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Payment Webhook Controller", description = "Controller xử lý webhook thanh toán từ PayOS")
@Hidden
public class PaymentWebhookController {

    private final PayOS payOS;
    private final OrderService orderService;
    private final OrderOfflineService orderOfflineService;
    private final PendingOrderCacheService pendingOrderCacheService;
    private final CartService cartService;
    private final StreamBridge streamBridge;

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

            // 2. TÌM ORDER TỪ REDIS TRƯỚC (cho PayOS orders)
            String orderId = pendingOrderCacheService.findOrderIdByPaymentCode(
                    webhookData.getOrderCode());

            if (orderId != null) {
                // Order đang pending trong Redis
                PendingOrderRedis pendingOrder = pendingOrderCacheService.getPendingOrder(orderId);

                if (pendingOrder != null) {
                    log.info("Found pending order in Redis: {}", pendingOrder.getOrderCode());

                    // 3a. Xử lý theo kết quả thanh toán
                    if ("00".equals(webhookData.getCode())) {
                        //  THÀNH CÔNG: Persist từ Redis vào DB
                        Order order = persistOrderFromRedis(pendingOrder, webhookData);

                        return ResponseEntity.ok(
                                ApiResponseDTO.success(
                                        "Thanh toán thành công, đơn hàng " + order.getOrderCode() + " đã được tạo",
                                        webhookData,
                                        HttpStatus.OK
                                )
                        );
                    } else {
                        // THẤT BẠI: Xóa khỏi Redis
                        handleFailedPaymentFromRedis(pendingOrder, webhookData);

                        return ResponseEntity.ok(
                                ApiResponseDTO.success(
                                        "Thanh toán thất bại, đơn hàng đã bị hủy - Code: " + webhookData.getCode(),
                                        webhookData,
                                        HttpStatus.OK
                                )
                        );
                    }
                }
            }

            // 3b. Nếu không tìm thấy trong Redis, tìm trong Database
            // (Trường hợp: COD orders hoặc offline orders đã được tạo trước)
            orderId = orderService.findOrderIdByPaymentOrderCode(webhookData.getOrderCode());

            if (orderId == null) {
                log.error("Order not found in Redis or DB for paymentOrderCode: {}",
                        webhookData.getOrderCode());
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                        ApiResponseDTO.error(
                                "Không tìm thấy đơn hàng với orderCode: " + webhookData.getOrderCode(),
                                HttpStatus.NOT_FOUND,
                                request.getRequestURI()
                        )
                );
            }

            // 4. Order đã tồn tại trong DB
            Order order = orderService.getOrderEntityById(orderId);

            if ("00".equals(webhookData.getCode())) {
                handleSuccessfulPayment(order, webhookData);

                return ResponseEntity.ok(
                        ApiResponseDTO.success(
                                "Thanh toán thành công cho đơn hàng " + order.getOrderCode(),
                                webhookData,
                                HttpStatus.OK
                        )
                );
            } else {
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
     * ========== REDIS FLOW ==========
     * Persist order từ Redis vào Database khi thanh toán thành công
     */
    private Order persistOrderFromRedis(
            PendingOrderRedis pendingOrder,
            WebhookData webhookData) {

        log.info("Persisting order from Redis to DB: {}", pendingOrder.getOrderCode());

        // Build CreateOrderRequest từ PendingOrderRedis
        CreateOrderRequest orderRequest = CreateOrderRequest.builder()
                .orderId(pendingOrder.getOrderId())
                .orderCode(pendingOrder.getOrderCode())
                .customerId(pendingOrder.getCustomerId())
                .eventId(pendingOrder.getEventId())
                .subTotal(pendingOrder.getSubTotal())
                .discountAmount(pendingOrder.getDiscountAmount())
                .totalPrice(pendingOrder.getTotalPrice())
                .shippingFee(pendingOrder.getShippingFee())
                .voucherUserId(pendingOrder.getVoucherUserId())
                .voucherCode(pendingOrder.getVoucherCode())
                .paymentMethod(pendingOrder.getPaymentMethod())
                .paymentOrderCode(pendingOrder.getPaymentOrderCode())
                .orderItems(pendingOrder.getItems())
                .shippingAddress(pendingOrder.getShippingAddress())
                .selectedRateId(pendingOrder.getSelectedRateId())
                .carrier(pendingOrder.getCarrier())
                .expectedDeliveryTime(pendingOrder.getExpectedDeliveryTime())
                .parcelWeight(pendingOrder.getParcelWeight())
                .parcelWidth(pendingOrder.getParcelWidth())
                .parcelHeight(pendingOrder.getParcelHeight())
                .parcelLength(pendingOrder.getParcelLength())
                .shippingStatus(pendingOrder.getShippingStatus())
                .isGuestPurchase(pendingOrder.getIsGuestPurchase())
                .guestName(pendingOrder.getGuestName())
                .guestPhone(pendingOrder.getGuestPhone())
                .earnedEcoPoints(pendingOrder.getEarnedEcoPoints())
                .note(pendingOrder.getNote())
                .build();

        // Set payment info từ webhook
        orderRequest.setPaymentStatus(PaymentStatus.PAID);
        orderRequest.setPaymentTransactionId(webhookData.getReference());

        // Set order status theo loại đơn
        if (OrderType.ONLINE.equals(pendingOrder.getOrderType())) {
            orderRequest.setOrderStatus(OrderStatus.PENDING);  // Đợi admin confirm
        } else if (OrderType.OFFLINE.equals(pendingOrder.getOrderType())) {
            orderRequest.setOrderStatus(OrderStatus.COMPLETED);  // Offline complete ngay
        }

        // Save vào Database
        Order savedOrder = orderService.buildAndSaveOrder(orderRequest);

        // Publish event theo loại đơn
        if (OrderType.ONLINE.equals(pendingOrder.getOrderType())) {
            // Online: CHỈ RESERVE sản phẩm, CHƯA cộng điểm
            publishOrderCheckedOutEventFromRedis(savedOrder);

            // Clear cart
            if (pendingOrder.getCustomerId() != null) {
                cartService.clearCart(pendingOrder.getCustomerId());
            }
        } else if (OrderType.OFFLINE.equals(pendingOrder.getOrderType())) {
            // Offline: SOLD sản phẩm + cộng điểm ngay
            orderOfflineService.publishOrderOfflineCreatedEventDelayed(savedOrder);
        }

        // Xóa khỏi Redis
        pendingOrderCacheService.deletePendingOrder(
                pendingOrder.getOrderId(),
                pendingOrder.getPaymentOrderCode()
        );

        log.info("Order {} persisted from Redis. Status: {}, Payment: {}",
                savedOrder.getOrderCode(),
                savedOrder.getOrderStatus(),
                savedOrder.getPaymentStatus());

        return savedOrder;
    }

    /**
     * Publish OrderCheckedOutEvent cho order từ Redis
     * CHỈ RESERVE sản phẩm, CHƯA cộng eco points
     */
    private void publishOrderCheckedOutEventFromRedis(Order order) {
        log.info("Publishing OrderCheckedOutEvent for order {} (from Redis)", order.getOrderId());

        List<OrderCheckedOutEvent.ProductStatusChange> productStatusChanges = new ArrayList<>();

        for (OrderItem item : order.getOrderItems()) {
            productStatusChanges.add(
                    OrderCheckedOutEvent.ProductStatusChange.builder()
                            .productId(item.getProductId())
                            .newStatus(ProductStatusConstant.RESERVED)
                            .ecoPointValue(0) // Không cộng điểm lúc checkout
                            .build()
            );
        }

        OrderCheckedOutEvent event = OrderCheckedOutEvent.builder()
                .orderId(order.getOrderId())
                .customerId(order.getCustomerId())
                .totalAmount(order.getTotalPrice())
                .checkedOutAt(order.getCreatedAt())
                .productStatusChanges(productStatusChanges)
                .totalEcoPoints(0) // Không cộng điểm
                .build();

        // CHỈ gửi đến Product Service
        streamBridge.send("orderCheckedOutProduct-out-0", event);

        log.info("Published OrderCheckedOutEvent (product reserve only) for order {}",
                order.getOrderId());
    }

    /**
     * Xử lý thanh toán thất bại - Xóa order khỏi Redis
     */
    private void handleFailedPaymentFromRedis(
            PendingOrderRedis pendingOrder,
            WebhookData webhookData) {

        log.warn("Payment failed for pending order {} - Code: {}, Desc: {}",
                pendingOrder.getOrderCode(),
                webhookData.getCode(),
                webhookData.getDesc());

        // Xóa khỏi Redis (không lưu vào DB)
        pendingOrderCacheService.deletePendingOrder(
                pendingOrder.getOrderId(),
                pendingOrder.getPaymentOrderCode()
        );

        // TODO: Gửi notification cho customer về payment failed

        log.info("Deleted failed pending order {} from Redis", pendingOrder.getOrderCode());
    }

    /**
     * ========== DATABASE FLOW ==========
     * Xử lý thanh toán thành công cho orders đã có trong DB
     * (COD orders hoặc Offline orders)
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
     * Xử lý thanh toán thất bại cho orders đã có trong DB
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

    /**
     * Confirm webhook URL với PayOS
     */
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
