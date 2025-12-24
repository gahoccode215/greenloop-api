package com.greenloop.order.service.impl;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.client.RewardClient;
import com.greenloop.order.constant.ProductStatusConstant;
import com.greenloop.order.dto.redis.PendingOrderRedis;
import com.greenloop.order.dto.request.*;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.exception.OrderNotFoundException;
import com.greenloop.order.service.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import vn.payos.model.webhooks.WebhookData;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class PaymentWebhookServiceImpl implements PaymentWebhookService {

    private final OrderService orderService;
    private final OrderOfflineService orderOfflineService;
    private final PendingOrderCacheService pendingOrderCacheService;
    private final CartService cartService;
    private final ProductClient productClient;
    private final RewardClient rewardClient;
    private final TransactionService transactionService;

    @Override
    @Transactional
    public String processPayOSWebhook(WebhookData webhookData) {
        log.info("Processing PayOS webhook - OrderCode: {}, Code: {}, Reference: {}",
                webhookData.getOrderCode(),
                webhookData.getCode(),
                webhookData.getDesc());

        // 1. TÌM ORDER TỪ REDIS TRƯỚC (cho PayOS orders)
        String orderId = pendingOrderCacheService.findOrderIdByPaymentCode(
                webhookData.getOrderCode());

        if (orderId != null) {
            return processOrderFromRedis(orderId, webhookData);
        }

        // 2. Nếu không tìm thấy trong Redis, tìm trong Database
        orderId = orderService.findOrderIdByPaymentOrderCode(webhookData.getOrderCode());

        if (orderId == null) {
            String errorMsg = "Order not found in Redis or DB for paymentOrderCode: "
                    + webhookData.getOrderCode();
            log.error(errorMsg);
            throw new OrderNotFoundException(errorMsg);
        }

        // 3. Order đã tồn tại trong DB
        return processOrderFromDatabase(orderId, webhookData);
    }

    /**
     * Xử lý order từ Redis
     */
    private String processOrderFromRedis(String orderId, WebhookData webhookData) {
        PendingOrderRedis pendingOrder = pendingOrderCacheService.getPendingOrder(orderId);

        if (pendingOrder == null) {
            log.warn("Pending order not found in Redis for orderId: {}", orderId);
            return processOrderFromDatabase(orderId, webhookData);
        }

        log.info("Found pending order in Redis: {}", pendingOrder.getOrderCode());

        if ("00".equals(webhookData.getCode())) {
            Order order = persistOrderFromRedis(pendingOrder, webhookData);
            return "Thanh toán thành công, đơn hàng " + order.getOrderCode() + " đã được tạo";
        } else {
            handleFailedPaymentFromRedis(pendingOrder, webhookData);
            return "Thanh toán thất bại, đơn hàng đã bị hủy - Code: " + webhookData.getCode();
        }
    }

    /**
     * Xử lý order từ Database
     */
    private String processOrderFromDatabase(String orderId, WebhookData webhookData) {
        Order order = orderService.getOrderEntityById(orderId);

        if ("00".equals(webhookData.getCode())) {
            handleSuccessfulPayment(order, webhookData);
            return "Thanh toán thành công cho đơn hàng " + order.getOrderCode();
        } else {
            handleFailedPayment(order, webhookData);
            return "Webhook nhận được nhưng thanh toán không thành công - Code: "
                    + webhookData.getCode();
        }
    }

    @Override
    @Transactional
    public Order persistOrderFromRedis(PendingOrderRedis pendingOrder, WebhookData webhookData) {
        log.info("Persisting order from Redis to DB: {}", pendingOrder.getOrderCode());

        CreateOrderRequest orderRequest = buildOrderRequestFromPendingOrder(pendingOrder, webhookData);

        // Save vào Database
        Order savedOrder = orderService.buildAndSaveOrder(orderRequest);

        // Xử lý theo loại đơn
        if (OrderType.ONLINE.equals(pendingOrder.getOrderType())) {
            handleOnlineOrderPersist(savedOrder, pendingOrder.getCustomerId());
        } else if (OrderType.OFFLINE.equals(pendingOrder.getOrderType())) {
            handleOfflineOrderPersist(savedOrder);
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

    @Override
    @Transactional
    public void handleSuccessfulPayment(Order order, WebhookData webhookData) {
        String orderId = order.getOrderId();
        OrderType orderType = order.getOrderType();

        orderService.updatePaymentStatus(orderId, PaymentStatus.PAID);
        orderService.updatePaymentTransactionId(orderId, webhookData.getReference());

        log.info("Processing successful payment for Order: {}, Type: {}",
                order.getOrderCode(), orderType);

        if (OrderType.OFFLINE.equals(orderType)) {
            handleOfflineOrderPayment(order);
        } else {
            handleOnlineOrderPayment(order);
        }
    }

    @Override
    @Transactional
    public void handleFailedPayment(Order order, WebhookData webhookData) {
        String orderId = order.getOrderId();
        orderService.updatePaymentStatus(orderId, PaymentStatus.FAILED);

        log.warn("Payment failed for order {} - Code: {}, Desc: {}",
                order.getOrderCode(),
                webhookData.getCode(),
                webhookData.getDesc());
    }

    @Override
    @Transactional
    public void handleFailedPaymentFromRedis(PendingOrderRedis pendingOrder, WebhookData webhookData) {
        log.warn("Payment failed for pending order {} - Code: {}, Desc: {}",
                pendingOrder.getOrderCode(),
                webhookData.getCode(),
                webhookData.getDesc());

        pendingOrderCacheService.deletePendingOrder(
                pendingOrder.getOrderId(),
                pendingOrder.getPaymentOrderCode()
        );

        log.info("Deleted failed pending order {} from Redis", pendingOrder.getOrderCode());
    }


    private CreateOrderRequest buildOrderRequestFromPendingOrder(
            PendingOrderRedis pendingOrder, WebhookData webhookData) {

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
            orderRequest.setOrderStatus(OrderStatus.PENDING);
        } else if (OrderType.OFFLINE.equals(pendingOrder.getOrderType())) {
            orderRequest.setOrderStatus(OrderStatus.COMPLETED);
        }

        return orderRequest;
    }

    /**
     * Xử lý ONLINE order - Reserve sản phẩm + mark voucher used
     */
    private void handleOnlineOrderPersist(Order order, Long customerId) {
        log.info("Processing ONLINE order {} via Feign", order.getOrderCode());

        // 1. Reserve products
        reserveProductsViaFeign(order);

        // 2. Tạo transaction
        transactionService.createTransactionFromOrder(order);

        // 3. Mark voucher as used (nếu có)
        if (order.getVoucherUserId() != null) {
            markVoucherAsUsedViaFeign(order);
        }

        // 4. Clear cart
        if (customerId != null) {
            cartService.clearCart(customerId);
        }

        log.info("ONLINE order {} processed: products RESERVED, voucher marked (if any)",
                order.getOrderCode());
    }

    /**
     * Xử lý OFFLINE order - SOLD sản phẩm + cộng điểm + mark voucher used
     */
    private void handleOfflineOrderPersist(Order order) {
        log.info("Processing OFFLINE order {} via Feign", order.getOrderCode());

        // 1. Mark products as SOLD
        markProductsAsSoldViaFeign(order);

        // 2. Complete transaction
        transactionService.completeTransaction(order.getOrderId());

        // 3. Add eco points
        int totalEcoPoints = order.getOrderItems().stream()
                .mapToInt(item -> item.getEcoPoint() != null ? item.getEcoPoint() : 0)
                .sum();

        if (totalEcoPoints > 0) {
            addEcoPointsViaFeign(order, totalEcoPoints);
        }

        // 4. Mark voucher as used (nếu có)
        if (order.getVoucherUserId() != null) {
            markVoucherAsUsedViaFeign(order);
        }

        log.info("OFFLINE order {} processed: products SOLD, {} eco points added, voucher marked (if any)",
                order.getOrderCode(), totalEcoPoints);
    }

    /**
     * Xử lý thanh toán thành công cho OFFLINE order đã có trong DB
     */
    private void handleOfflineOrderPayment(Order order) {
        String orderId = order.getOrderId();

        orderService.updateOrderStatus(orderId, OrderStatus.COMPLETED);
        orderOfflineService.publishOrderOfflineCreatedEventDelayed(order);

        log.info("Offline order {} completed after PayOS payment", order.getOrderCode());
    }

    /**
     * Xử lý thanh toán thành công cho ONLINE order đã có trong DB
     */
    private void handleOnlineOrderPayment(Order order) {
        String orderId = order.getOrderId();
        OrderStatus currentStatus = order.getOrderStatus();

        if (OrderStatus.PENDING.equals(currentStatus)) {
            orderService.updateOrderStatus(orderId, OrderStatus.PENDING);
            log.info("Online order {} payment confirmed. Status remains PENDING",
                    order.getOrderCode());
        } else {
            log.warn("Online order {} already in status {}. Skipping status update.",
                    order.getOrderCode(), currentStatus);
        }
    }


    /**
     * Reserve products qua Product Service
     */
    private void reserveProductsViaFeign(Order order) {
        log.info("Reserving products via Feign for order: {}", order.getOrderCode());

        List<ReserveProductsRequest.ProductReserve> products = order.getOrderItems().stream()
                .map(item -> ReserveProductsRequest.ProductReserve.builder()
                        .productId(item.getProductId())
                        .build())
                .collect(Collectors.toList());

        ReserveProductsRequest request = ReserveProductsRequest.builder()
                .orderId(order.getOrderId())
                .customerId(order.getCustomerId())
                .products(products)
                .build();

        try {
            ApiResponseDTO<Void> response = productClient.reserveProducts(request);
            if (!response.isSuccess()) {
                log.error("Failed to reserve products for order: {}", order.getOrderCode());
            } else {
                log.info("Reserved {} products for order: {}", products.size(), order.getOrderCode());
            }
        } catch (Exception e) {
            log.error("Error calling product service to reserve products", e);
        }
    }

    /**
     * Mark products as SOLD qua Product Service
     */
    private void markProductsAsSoldViaFeign(Order order) {
        log.info("Marking products as SOLD via Feign for order: {}", order.getOrderCode());

        List<MarkProductsSoldRequest.ProductSold> products = order.getOrderItems().stream()
                .map(item -> MarkProductsSoldRequest.ProductSold.builder()
                        .productId(item.getProductId())
                        .ecoPointValue(item.getEcoPoint() != null ? item.getEcoPoint() : 0)
                        .build())
                .collect(Collectors.toList());

        MarkProductsSoldRequest request = MarkProductsSoldRequest.builder()
                .orderId(order.getOrderId())
                .products(products)
                .build();

        try {
            ApiResponseDTO<Void> response = productClient.markProductsAsSold(request);
            if (!response.isSuccess()) {
                log.error("Failed to mark products as SOLD for order: {}", order.getOrderCode());
            } else {
                log.info("Marked {} products as SOLD for order: {}", products.size(), order.getOrderCode());
            }
        } catch (Exception e) {
            log.error("Error calling product service to mark as sold", e);
        }
    }

    /**
     * Add eco points qua Reward Service
     */
    private void addEcoPointsViaFeign(Order order, int totalEcoPoints) {
        log.info("Adding {} eco points via Feign for order: {}",
                totalEcoPoints, order.getOrderCode());

        AddEcoPointsRequest request = AddEcoPointsRequest.builder()
                .orderId(order.getOrderId())
                .orderCode(order.getOrderCode())
                .customerId(order.getCustomerId())
                .ecoPoints(totalEcoPoints)
                .orderAmount(order.getTotalPrice())
                .earnedAt(LocalDateTime.now())
                .build();

        try {
            ApiResponseDTO<Void> response = rewardClient.addEcoPoints(request);
            if (!response.isSuccess()) {
                log.error("Failed to add eco points for order: {}", order.getOrderCode());
            } else {
                log.info("Added {} eco points successfully for order: {}",
                        totalEcoPoints, order.getOrderCode());
            }
        } catch (Exception e) {
            log.error("Error calling reward service to add eco points", e);
        }
    }

    /**
     * Mark voucher as used qua Reward Service
     */
    private void markVoucherAsUsedViaFeign(Order order) {
        log.info("Marking voucher as used via Feign for order: {}, voucherUserId: {}",
                order.getOrderCode(), order.getVoucherUserId());

        VoucherUsedRequest request = VoucherUsedRequest.builder()
                .orderId(order.getOrderId())
                .orderCode(order.getOrderCode())
                .customerId(order.getCustomerId())
                .voucherUserId(order.getVoucherUserId())
                .voucherCode(order.getVoucherCode())
                .discountValue(order.getDiscountAmount())
                .usedAt(order.getCreatedAt())
                .build();

        try {
            ApiResponseDTO<Void> response = rewardClient.markVoucherAsUsed(request);
            if (!response.isSuccess()) {
                log.error("Failed to mark voucher as used for order: {}", order.getOrderCode());
            } else {
                log.info("Voucher marked as used successfully for voucherUserId: {}",
                        order.getVoucherUserId());
            }
        } catch (Exception e) {
            log.error("Error calling reward service to mark voucher as used", e);
        }
    }
}
