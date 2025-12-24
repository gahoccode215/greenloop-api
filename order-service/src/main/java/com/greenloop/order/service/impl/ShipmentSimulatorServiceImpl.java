package com.greenloop.order.service.impl;

import com.greenloop.order.dto.simulator.ReturnShipmentSimulatorResponse;
import com.greenloop.order.dto.simulator.ShipmentSimulatorResponse;
import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.ReturnRequest;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.ReturnRequestStatus;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.repository.ReturnRequestRepository;
import com.greenloop.order.service.ShipmentSimulatorService;
import com.greenloop.order.util.ShippingStatusMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class ShipmentSimulatorServiceImpl implements ShipmentSimulatorService {

    private final OrderRepository orderRepository;
    private final ReturnRequestRepository returnRequestRepository;

    @Override
    @Transactional(readOnly = true)
    public List<ShipmentSimulatorResponse> getActiveShipments() {
        List<Order> activeOrders = orderRepository.findActiveShipments(
                List.of(
                        OrderStatus.READY_TO_SHIP,
                        OrderStatus.SHIPPING,
                        OrderStatus.DELIVERING,
                        OrderStatus.DELIVERED,
                        OrderStatus.DELIVERY_FAILED,
                        OrderStatus.RETURNING
                )
        );

        return activeOrders.stream()
                .map(this::mapToSimulatorResponse)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<ReturnShipmentSimulatorResponse> getActiveReturnShipments() {
        List<ReturnRequest> activeReturnRequests = returnRequestRepository
                .findByStatusIn(List.of(
                        ReturnRequestStatus.READY_TO_RETURN,
                        ReturnRequestStatus.RETURNING,
                        ReturnRequestStatus.RETURNED_TO_WAREHOUSE
                ));

        return activeReturnRequests.stream()
                .filter(rr -> rr.getReturnShipmentId() != null)
                .map(this::mapToReturnSimulatorResponse)
                .collect(Collectors.toList());
    }


    private ShipmentSimulatorResponse mapToSimulatorResponse(Order order) {
        ShipmentSimulatorResponse.ShipmentSimulatorResponseBuilder builder =
                ShipmentSimulatorResponse.builder()
                        .orderId(order.getOrderId())
                        .orderCode(order.getOrderCode())
                        .goshipShipmentId(order.getGoshipShipmentId())
                        .goshipTrackingUrl(order.getGoshipTrackingUrl())
                        .carrier(order.getCarrier())
                        .currentShippingStatus(order.getShippingStatus())
                        .currentShippingStatusText(ShippingStatusMapper.getStatusText(
                                order.getShippingStatus()))
                        .orderStatus(order.getOrderStatus().name())
                        .orderStatusDescription(order.getOrderStatus().getDescription())
                        .parcelWeight(order.getParcelWeight())
                        .parcelLength(order.getParcelLength())
                        .parcelWidth(order.getParcelWidth())
                        .parcelHeight(order.getParcelHeight())
                        .totalPrice(order.getTotalPrice())
                        .paymentMethod(order.getPaymentMethod() != null
                                ? order.getPaymentMethod().name() : null)
                        .paymentStatus(order.getPaymentStatus() != null
                                ? order.getPaymentStatus().name() : null)
                        .createdAt(order.getCreatedAt())
                        .expectedDeliveryTime(order.getExpectedDeliveryTime())
                        .updatedAt(order.getUpdatedAt());

        if (order.getShippingAddress() != null) {
            builder.receiverName(order.getShippingAddress().getReceiverName())
                    .receiverPhone(order.getShippingAddress().getReceiverPhone())
                    .receiverAddress(order.getShippingAddress().getReceiverAddress())
                    .receiverWardName(order.getShippingAddress().getReceiverWardName())
                    .receiverDistrictName(order.getShippingAddress().getReceiverDistrictName())
                    .receiverCityName(order.getShippingAddress().getReceiverCityName())
                    .note(order.getShippingAddress().getNote())
                    .warehouseName(order.getShippingAddress().getWarehouseName())
                    .warehousePhone(order.getShippingAddress().getWarehousePhone())
                    .warehouseAddress(order.getShippingAddress().getWarehouseAddress())
                    .warehouseWardName(order.getShippingAddress().getWarehouseWardName())
                    .warehouseDistrictName(order.getShippingAddress().getWarehouseDistrictName())
                    .warehouseCityName(order.getShippingAddress().getWarehouseCityName());
        }

        return builder.build();
    }

    private ReturnShipmentSimulatorResponse mapToReturnSimulatorResponse(ReturnRequest returnRequest) {
        Order order = orderRepository.findById(returnRequest.getOrderId()).orElse(null);

        ReturnShipmentSimulatorResponse.ReturnShipmentSimulatorResponseBuilder builder =
                ReturnShipmentSimulatorResponse.builder()
                        .returnRequestId(returnRequest.getReturnRequestId())
                        .orderId(returnRequest.getOrderId())
                        .orderCode(order != null ? order.getOrderCode() : null)
                        .customerId(returnRequest.getCustomerId())
                        .returnShipmentId(returnRequest.getReturnShipmentId())
                        .returnTrackingUrl(returnRequest.getReturnTrackingUrl())
                        .returnCarrier(returnRequest.getReturnCarrier())
                        .currentReturnShippingStatus(returnRequest.getReturnShippingStatus())
                        .currentReturnShippingStatusText(ShippingStatusMapper.getStatusText(
                                returnRequest.getReturnShippingStatus()))
                        .returnRequestStatus(returnRequest.getStatus().name())
                        .returnRequestStatusText(returnRequest.getStatus().getDescription())
                        .returnReason(returnRequest.getReturnReason().name())
                        .returnType(returnRequest.getReturnType().name())
                        .originalAmount(returnRequest.getOriginalAmount())
                        .refundAmount(returnRequest.getRefundAmount())
                        .requestedAt(returnRequest.getRequestedAt())
                        .approvedAt(returnRequest.getApprovedAt())
                        .returnedAt(returnRequest.getReturnedAt())
                        .completedAt(returnRequest.getCompletedAt())
                        .createdAt(returnRequest.getCreatedAt())
                        .updatedAt(returnRequest.getUpdatedAt());

        if (order != null && order.getShippingAddress() != null) {
            builder.pickupName(order.getShippingAddress().getReceiverName())
                    .pickupPhone(order.getShippingAddress().getReceiverPhone())
                    .pickupAddress(order.getShippingAddress().getReceiverAddress())
                    .pickupWardName(order.getShippingAddress().getReceiverWardName())
                    .pickupDistrictName(order.getShippingAddress().getReceiverDistrictName())
                    .pickupCityName(order.getShippingAddress().getReceiverCityName())
                    .warehouseName(order.getShippingAddress().getWarehouseName())
                    .warehousePhone(order.getShippingAddress().getWarehousePhone())
                    .warehouseAddress(order.getShippingAddress().getWarehouseAddress())
                    .warehouseWardName(order.getShippingAddress().getWarehouseWardName())
                    .warehouseDistrictName(order.getShippingAddress().getWarehouseDistrictName())
                    .warehouseCityName(order.getShippingAddress().getWarehouseCityName());
        }

        return builder.build();
    }
}
