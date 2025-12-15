package com.greenloop.order.service.impl;

import com.greenloop.order.dto.simulator.ShipmentSimulatorResponse;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.repository.OrderRepository;
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

    @Override
    @Transactional(readOnly = true)
    public List<ShipmentSimulatorResponse> getActiveShipments() {
        log.info("Fetching active shipments for simulator");

        // Lấy các đơn hàng đang active (chưa hoàn thành/hủy/thất lạc/hoàn trả)
        List<Order> activeOrders = orderRepository.findActiveShipments(
                List.of(
                        OrderStatus.READY_TO_SHIP,    // Chờ lấy hàng
                        OrderStatus.SHIPPING,          // Đã lấy hàng
                        OrderStatus.DELIVERING,        // Đang giao
                        OrderStatus.DELIVERED,         // Đã giao (chờ staff complete)
                        OrderStatus.DELIVERY_FAILED,   // Giao thất bại
                        OrderStatus.RETURNING          // Đang hoàn
                )
        );

        log.info("Found {} active shipments", activeOrders.size());

        return activeOrders.stream()
                .map(this::mapToSimulatorResponse)
                .collect(Collectors.toList());
    }

    /**
     * Map Order entity sang ShipmentSimulatorResponse
     */
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

        // Map thông tin shipping address nếu có
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
}
