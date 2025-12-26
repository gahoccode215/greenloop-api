package com.greenloop.order.service.impl;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.client.RewardClient;
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
        String orderId = pendingOrderCacheService.findOrderIdByPaymentCode(
                webhookData.getOrderCode());

        if (orderId != null) {
            return processOrderFromRedis(orderId, webhookData);
        }

        String errorMsg = "Order not found in Redis or DB for paymentOrderCode: "
                + webhookData.getOrderCode();
        log.error(errorMsg);
        throw new OrderNotFoundException(errorMsg);
    }

    private String processOrderFromRedis(String orderId, WebhookData webhookData) {
        PendingOrderRedis pendingOrder = pendingOrderCacheService.getPendingOrder(orderId);
        if ("00".equals(webhookData.getCode())) {
            Order order = persistOrderFromRedis(pendingOrder, webhookData);
            return "Thanh toán thành công, đơn hàng " + order.getOrderCode() + " đã được tạo";
        } else {
            handleFailedPaymentFromRedis(pendingOrder, webhookData);
            return "Thanh toán thất bại, đơn hàng đã bị hủy - Code: " + webhookData.getCode();
        }
    }


    @Override
    @Transactional
    public Order persistOrderFromRedis(PendingOrderRedis pendingOrder, WebhookData webhookData) {
        CreateOrderRequest orderRequest = buildOrderRequestFromPendingOrder(pendingOrder, webhookData);
        Order savedOrder = orderService.buildAndSaveOrder(orderRequest);
        if (OrderType.ONLINE.equals(pendingOrder.getOrderType())) {
            handleOnlineOrderPersist(savedOrder, pendingOrder.getCustomerId());
        } else if (OrderType.OFFLINE.equals(pendingOrder.getOrderType())) {
            handleOfflineOrderPersist(savedOrder);
        }
        pendingOrderCacheService.deletePendingOrder(
                pendingOrder.getOrderId(),
                pendingOrder.getPaymentOrderCode()
        );
        return savedOrder;
    }

    @Override
    @Transactional
    public void handleFailedPaymentFromRedis(PendingOrderRedis pendingOrder, WebhookData webhookData) {
        pendingOrderCacheService.deletePendingOrder(
                pendingOrder.getOrderId(),
                pendingOrder.getPaymentOrderCode()
        );

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
        orderRequest.setPaymentStatus(PaymentStatus.PAID);
        orderRequest.setPaymentTransactionId(webhookData.getReference());
        if (OrderType.ONLINE.equals(pendingOrder.getOrderType())) {
            orderRequest.setOrderStatus(OrderStatus.PENDING);
        } else if (OrderType.OFFLINE.equals(pendingOrder.getOrderType())) {
            orderRequest.setOrderStatus(OrderStatus.COMPLETED);
        }

        return orderRequest;
    }

    private void handleOnlineOrderPersist(Order order, Long customerId) {
        reserveProductsViaFeign(order);
        if (order.getVoucherUserId() != null) {
            markVoucherAsUsedViaFeign(order);
        }
        if (customerId != null) {
            cartService.clearCart(customerId);
        }
    }

    private void handleOfflineOrderPersist(Order order) {
        markProductsAsSoldViaFeign(order);
        transactionService.createTransactionForOfflineOrder(order);
        int totalEcoPoints = order.getOrderItems().stream()
                .mapToInt(item -> item.getEcoPoint() != null ? item.getEcoPoint() : 0)
                .sum();
        if (totalEcoPoints > 0) {
            addEcoPointsViaFeign(order, totalEcoPoints);
        }
        if (order.getVoucherUserId() != null) {
            markVoucherAsUsedViaFeign(order);
        }
    }

    private void reserveProductsViaFeign(Order order) {
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

    private void markProductsAsSoldViaFeign(Order order) {
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

    private void addEcoPointsViaFeign(Order order, int totalEcoPoints) {
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

    private void markVoucherAsUsedViaFeign(Order order) {
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
