package com.greenloop.order.goship.service;

import com.greenloop.order.client.ProductClient;
import com.greenloop.order.client.RewardClient;
import com.greenloop.order.constant.ProductStatusConstant;
import com.greenloop.order.dto.request.*;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.ReturnRequest;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.enums.ReturnRequestStatus;
import com.greenloop.order.exception.OrderNotFoundException;
import com.greenloop.order.exception.ReturnRequestNotFoundException;
import com.greenloop.order.goship.dto.GoShipWebhookPayload;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.repository.ReturnRequestRepository;
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
    private final ReturnRequestRepository returnRequestRepository;
    private final OrderService orderService;
    private final ProductClient productClient;
    private final TransactionService transactionService;
    private final RewardClient rewardClient;

    @Transactional
    public void handleWebhook(GoShipWebhookPayload payload) {
        // KIỂM TRA IS_RETURN để phân luồng
        if (payload.getIsReturn() != null && payload.getIsReturn() == 1) {
            handleReturnWebhook(payload);
            return;
        }

        // XỬ LÝ ORDER BÌNH THƯỜNG
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

    // THÊM METHOD MỚI CHO RETURN WEBHOOK
    @Transactional
    public void handleReturnWebhook(GoShipWebhookPayload payload) {
        String orderId = payload.getOrderId();

        log.info("Processing return webhook for orderId: {}", orderId);

        // orderId format: "RR-{returnRequestId}-{orderCode}"
        if (!orderId.startsWith("RR-")) {
            log.warn("Invalid return order ID format: {}", orderId);
            return;
        }

        String[] parts = orderId.split("-", 3);
        if (parts.length < 2) {
            log.warn("Cannot parse return request ID from: {}", orderId);
            return;
        }

        Long returnRequestId;
        try {
            returnRequestId = Long.parseLong(parts[1]);
        } catch (NumberFormatException e) {
            log.error("Invalid return request ID format: {}", parts[1]);
            return;
        }

        ReturnRequest returnRequest = returnRequestRepository.findById(returnRequestId)
                .orElseThrow(() -> new ReturnRequestNotFoundException(
                        "ReturnRequest not found for GoShip shipment: " + payload.getGcode()));

        Integer newShippingStatus = Integer.parseInt(payload.getStatus());

        log.info("GoShip return webhook received. ReturnRequest: {}, Status: {} ({})",
                returnRequestId, newShippingStatus, payload.getStatusText());

        if (payload.getTrackingUrl() != null) {
            returnRequest.setReturnTrackingUrl(payload.getTrackingUrl());
        }
        returnRequest.setReturnShippingStatus(newShippingStatus);

        handleReturnShippingStatusChange(returnRequest, newShippingStatus, payload);

        returnRequest.setUpdatedAt(LocalDateTime.now());
        returnRequestRepository.save(returnRequest);
    }

    // THÊM METHOD XỬ LÝ RETURN SHIPPING STATUS
    private void handleReturnShippingStatusChange(ReturnRequest returnRequest,
                                                  Integer goshipStatus,
                                                  GoShipWebhookPayload payload) {
        switch (goshipStatus) {
            case 903: // Đã lấy hàng từ customer
                log.info("GoShip picked up return items for ReturnRequest {}",
                        returnRequest.getReturnRequestId());
                break;

            case 904: // Đang vận chuyển về kho
                log.info("Return items in transit for ReturnRequest {}",
                        returnRequest.getReturnRequestId());
                break;

            case 905: // Giao hàng thành công (đã về kho)
                log.info("Return items delivered to warehouse for ReturnRequest {}",
                        returnRequest.getReturnRequestId());

                // Tự động chuyển sang RETURNED_TO_WAREHOUSE
                if (returnRequest.getStatus() == ReturnRequestStatus.RETURNING) {
                    returnRequest.setStatus(ReturnRequestStatus.RETURNED_TO_WAREHOUSE);
                    returnRequest.setReturnedAt(LocalDateTime.now());
                    log.info("ReturnRequest {} auto-updated to RETURNED_TO_WAREHOUSE",
                            returnRequest.getReturnRequestId());
                }
                break;

            case 906: // Giao hàng thất bại
            case 915: // Hoàn về người gửi (customer giữ lại)
                log.warn("Return delivery failed for ReturnRequest {}. Status: {} ({})",
                        returnRequest.getReturnRequestId(), goshipStatus, payload.getStatusText());
                break;

            case 917: // Thất lạc hàng
                log.error("Return items LOST for ReturnRequest {}",
                        returnRequest.getReturnRequestId());
                break;

            default:
                log.debug("ReturnRequest {} shipping status updated to {}",
                        returnRequest.getReturnRequestId(), goshipStatus);
                break;
        }
    }

    // CÁC METHOD CŨ GIỮ NGUYÊN...
    private void handleProductStatusChange(Order order, Integer goshipStatus, GoShipWebhookPayload payload) {
        String newProductStatus;
        String oldProductStatus;

        switch (goshipStatus) {
            case 903:
            case 904:
                oldProductStatus = ProductStatusConstant.RESERVED;
                newProductStatus = ProductStatusConstant.IN_TRANSIT;

                log.info("GoShip picked up order {} - Product: RESERVED -> IN_TRANSIT (Xuất kho)",
                        order.getOrderCode());

                updateProductStatusViaFeign(order, oldProductStatus, newProductStatus);
                break;

            case 917:
                oldProductStatus = ProductStatusConstant.IN_TRANSIT;
                newProductStatus = ProductStatusConstant.LOST;

                log.error("Order {} products marked as LOST", order.getOrderCode());

                updateProductStatusViaFeign(order, oldProductStatus, newProductStatus);
                orderService.handleLostOrder(order.getOrderId(), payload.getMessage());
                break;

            default:
                break;
        }
    }

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

    private void handlePaymentStatusForDelivered(Order order, Integer goshipStatus,
                                                 GoShipWebhookPayload payload) {
        if (goshipStatus == 905) {
            int totalEcoPoints = order.getOrderItems().stream()
                    .mapToInt(item -> item.getEcoPoint() != null ? item.getEcoPoint() : 0)
                    .sum();

            order.setEarnedEcoPoints(totalEcoPoints);

            log.info("Order {} earned {} eco points",
                    order.getOrderCode(), totalEcoPoints);

            if (order.getPaymentMethod() == PaymentMethod.COD
                    && order.getPaymentStatus() == PaymentStatus.UNPAID) {

                order.setPaymentStatus(PaymentStatus.PAID);

                log.info("COD Order {} marked as PAID after successful delivery. Customer paid: {}",
                        order.getOrderCode(), payload.getCod());
            }

            processOrderCompleted(order, totalEcoPoints);
        }
    }

    private void processOrderCompleted(Order order, int totalEcoPoints) {
        log.info("Processing completed order {}", order.getOrderCode());

        transactionService.completeTransaction(order.getOrderId());
        markProductsAsSoldViaFeign(order);

        if (totalEcoPoints > 0) {
            addEcoPointsViaFeign(order, totalEcoPoints);
        }
    }

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
