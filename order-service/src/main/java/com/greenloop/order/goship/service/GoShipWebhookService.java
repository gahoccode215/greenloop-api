package com.greenloop.order.goship.service;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.client.RewardClient;
import com.greenloop.order.constant.ProductStatusConstant;
import com.greenloop.order.dto.request.*;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.exception.OrderNotFoundException;
import com.greenloop.order.goship.dto.GoShipWebhookPayload;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.service.OrderService;
import com.greenloop.order.service.TransactionService;
import com.greenloop.order.util.OrderStatusSyncMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class GoShipWebhookService {

    private final OrderRepository orderRepository;
    private final OrderService orderService;
    private final ProductClient productClient;
    private final TransactionService transactionService;
    private final RewardClient rewardClient;

    @Transactional
    public void handleWebhook(GoShipWebhookPayload payload) {
        String orderId = payload.getOrderId();
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new OrderNotFoundException(
                        "Order not found for GoShip shipment: " + payload.getGcode()));

        OrderStatus oldOrderStatus = order.getOrderStatus();
        Integer newShippingStatus = Integer.parseInt(payload.getStatus());

        if (payload.getTrackingUrl() != null) {
            order.setGoshipTrackingUrl(payload.getTrackingUrl());
        }
        order.setShippingStatus(newShippingStatus);

        OrderStatus targetOrderStatus = OrderStatusSyncMapper.getTargetOrderStatus(
                newShippingStatus, oldOrderStatus);

        if (targetOrderStatus != null && targetOrderStatus != oldOrderStatus) {
            order.setOrderStatus(targetOrderStatus);
        }

        handlePaymentStatusForDelivered(order, newShippingStatus, payload);

        order.setUpdatedAt(LocalDateTime.now());
        orderRepository.save(order);

        handleProductStatusChange(order, newShippingStatus, payload);
    }

    /**
     * Xử lý thay đổi trạng thái sản phẩm theo GoShip status
     */
    private void handleProductStatusChange(Order order, Integer goshipStatus, GoShipWebhookPayload payload) {
        String newProductStatus;
        String oldProductStatus;

        switch (goshipStatus) {
            case 903: // Đã lấy hàng - xuất kho
            case 904: // Đang vận chuyển
                oldProductStatus = ProductStatusConstant.RESERVED;
                newProductStatus = ProductStatusConstant.IN_TRANSIT;

                log.info("GoShip picked up order {} - Product: RESERVED -> IN_TRANSIT (Xuất kho)",
                        order.getOrderCode());

                updateProductStatusViaFeign(order, oldProductStatus, newProductStatus);
                break;

            case 917: // Thất lạc hàng
                oldProductStatus = ProductStatusConstant.IN_TRANSIT;
                newProductStatus = ProductStatusConstant.LOST;

                log.error("Order {} products marked as LOST", order.getOrderCode());

                updateProductStatusViaFeign(order, oldProductStatus, newProductStatus);

                // Xử lý business cho LOST (COD/PayOS, thông báo, khiếu nại...)
                orderService.handleLostOrder(order.getOrderId(), payload.getMessage());
                break;

            default:
                // Các status khác không update product
                break;
        }
    }

    /**
     * ✅ Update product status qua Product Service (FEIGN)
     */
    private void updateProductStatusViaFeign(Order order, String oldStatus, String newStatus) {
        log.info("Updating product status via Feign for order {}: {} -> {}",
                order.getOrderCode(), oldStatus, newStatus);

        List<UpdateProductStatusRequest.ProductStatusUpdate> productUpdates =
                order.getOrderItems().stream()
                        .map(item -> UpdateProductStatusRequest.ProductStatusUpdate.builder()
                                .productId(item.getProductId())
                                .oldStatus(oldStatus)
                                .newStatus(newStatus)
                                .build())
                        .collect(Collectors.toList());

        UpdateProductStatusRequest request = UpdateProductStatusRequest.builder()
                .orderId(order.getOrderId())
                .orderCode(order.getOrderCode())
                .productUpdates(productUpdates)
                .updatedAt(LocalDateTime.now())
                .build();

        try {
            ApiResponseDTO<Void> response = productClient.updateProductStatus(request);
            if (!response.isSuccess()) {
                log.error("Failed to update product status for order: {}", order.getOrderCode());
            } else {
                log.info("Updated {} products: {} -> {} for order: {}",
                        productUpdates.size(), oldStatus, newStatus, order.getOrderCode());
            }
        } catch (Exception e) {
            log.error("Error calling product service to update status", e);
        }
    }

    /**
     * Xử lý payment status và tính eco points cho delivered orders
     */
    private void handlePaymentStatusForDelivered(Order order, Integer goshipStatus,
                                                 GoShipWebhookPayload payload) {
        // Status 905: Giao hàng thành công
        if (goshipStatus == 905) {
            // 1. Tính tổng eco points từ OrderItem
            int totalEcoPoints = order.getOrderItems().stream()
                    .mapToInt(item -> item.getEcoPoint() != null ? item.getEcoPoint() : 0)
                    .sum();

            // 2. Lưu vào earnedEcoPoints
            order.setEarnedEcoPoints(totalEcoPoints);

            log.info("Order {} earned {} eco points",
                    order.getOrderCode(), totalEcoPoints);

            // 3. Nếu là COD và chưa thanh toán thì đánh dấu đã thanh toán
            if (order.getPaymentMethod() == PaymentMethod.COD
                    && order.getPaymentStatus() == PaymentStatus.UNPAID) {

                order.setPaymentStatus(PaymentStatus.PAID);

                log.info("COD Order {} marked as PAID after successful delivery. Customer paid: {}",
                        order.getOrderCode(), payload.getCod());
            }

            // ✅ Xử lý order completed qua Feign
            processOrderCompleted(order, totalEcoPoints);
        }
    }

    /**
     * ✅ Xử lý khi order completed (THAY CHO publishOrderCompletedEvents)
     */
    private void processOrderCompleted(Order order, int totalEcoPoints) {
        log.info("Processing completed order {}", order.getOrderCode());

        // 1. ✅ Tạo transaction cho COD (nếu chưa có)
        transactionService.completeTransaction(order.getOrderId());

        // 2. ✅ Mark products as SOLD via Feign
        markProductsAsSoldViaFeign(order);

        // 3. ✅ Add eco points via Feign
        if (totalEcoPoints > 0) {
            addEcoPointsViaFeign(order, totalEcoPoints);
        }
    }

    /**
     * ✅ Mark products as SOLD qua Product Service
     */
    private void markProductsAsSoldViaFeign(Order order) {
        log.info("Marking products as SOLD via Feign for order: {}", order.getOrderCode());

        List<MarkProductsSoldRequest.ProductSold> products = order.getOrderItems().stream()
                .map(item -> MarkProductsSoldRequest.ProductSold.builder()
                        .productId(item.getProductId())
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
                log.info("Marked {} products as SOLD for order: {}",
                        products.size(), order.getOrderCode());
            }
        } catch (Exception e) {
            log.error("Error calling product service to mark products as SOLD", e);
        }
    }

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
                log.info("Added {} eco points for order: {}",
                        totalEcoPoints, order.getOrderCode());
            }
        } catch (Exception e) {
            log.error("Error calling reward service to add eco points", e);
        }
    }
}
