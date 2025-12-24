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
        if (payload.getIsReturn() != null && payload.getIsReturn() == 1) {
            handleReturnWebhook(payload);
            return;
        }
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

        handlePaymentStatusForDelivered(order, newShippingStatus);
        order.setUpdatedAt(LocalDateTime.now());
        orderRepository.save(order);
        handleProductStatusChange(order, newShippingStatus, payload);
    }

    @Transactional
    public void handleReturnWebhook(GoShipWebhookPayload payload) {
        String orderId = payload.getOrderId();
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
        if (payload.getTrackingUrl() != null) {
            returnRequest.setReturnTrackingUrl(payload.getTrackingUrl());
        }
        returnRequest.setReturnShippingStatus(newShippingStatus);
        handleReturnShippingStatusChange(returnRequest, newShippingStatus, payload);
        returnRequest.setUpdatedAt(LocalDateTime.now());
        returnRequestRepository.save(returnRequest);
    }

    private void handleReturnShippingStatusChange(ReturnRequest returnRequest,
                                                  Integer goshipStatus,
                                                  GoShipWebhookPayload payload) {
        ReturnRequestStatus currentStatus = returnRequest.getStatus();

        switch (goshipStatus) {
            case 900:
            case 901:
            case 902:
                break;

            case 903:
                if (currentStatus == ReturnRequestStatus.READY_TO_RETURN) {
                    returnRequest.setStatus(ReturnRequestStatus.RETURNING);
                }
                break;

            case 904:
            case 919:
                if (currentStatus == ReturnRequestStatus.READY_TO_RETURN) {
                    returnRequest.setStatus(ReturnRequestStatus.RETURNING);
                }
                break;

            case 905:
                if (currentStatus == ReturnRequestStatus.RETURNING) {
                    returnRequest.setStatus(ReturnRequestStatus.RETURNED_TO_WAREHOUSE);
                    returnRequest.setReturnedAt(LocalDateTime.now());
                }
                break;

            case 906:
                returnRequest.setStatus(ReturnRequestStatus.RETURN_FAILED);
                break;

            case 915:
                break;

            case 917:
                break;

            case 914:
                returnRequest.setStatus(ReturnRequestStatus.CANCELLED);
                break;

            default:
                break;
        }
    }


    private void handleProductStatusChange(Order order, Integer goshipStatus, GoShipWebhookPayload payload) {
        String newProductStatus;
        String oldProductStatus;
        switch (goshipStatus) {
            case 903:
            case 904:
                oldProductStatus = ProductStatusConstant.RESERVED;
                newProductStatus = ProductStatusConstant.IN_TRANSIT;
                updateProductStatusViaFeign(order, oldProductStatus, newProductStatus);
                break;
            case 917:
                oldProductStatus = ProductStatusConstant.IN_TRANSIT;
                newProductStatus = ProductStatusConstant.LOST;
                updateProductStatusViaFeign(order, oldProductStatus, newProductStatus);
                orderService.handleLostOrder(order.getOrderId(), payload.getMessage());
                break;

            default:
                break;
        }
    }

    private void updateProductStatusViaFeign(Order order, String oldStatus, String newStatus) {
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

    private void handlePaymentStatusForDelivered(Order order, Integer goshipStatus) {
        if (goshipStatus == 905) {
            if (order.getPaymentMethod() == PaymentMethod.COD
                    && order.getPaymentStatus() == PaymentStatus.UNPAID) {
                order.setPaymentStatus(PaymentStatus.PAID);
            }

            order.setDeliveredAt(LocalDateTime.now());

        }
    }

}
