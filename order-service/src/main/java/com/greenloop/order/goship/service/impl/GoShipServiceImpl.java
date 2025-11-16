package com.greenloop.order.goship.service.impl;

import com.greenloop.order.entity.Order;
import com.greenloop.order.goship.client.GoShipClient;
import com.greenloop.order.goship.dto.*;
import com.greenloop.order.goship.service.GoShipService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class GoShipServiceImpl implements GoShipService {

    private final GoShipClient goShipClient;

    @Value("${goship.default-warehouse.city}")
    private String defaultWarehouseCity;

    @Value("${goship.default-warehouse.district}")
    private String defaultWarehouseDistrict;

    @Value("${goship.default-warehouse.ward}")
    private String defaultWarehouseWard;

    @Value("${goship.default-warehouse.address}")
    private String defaultWarehouseAddress;

    @Value("${goship.default-warehouse.name}")
    private String defaultWarehouseName;

    @Value("${goship.default-warehouse.phone}")
    private String defaultWarehousePhone;

    @Override
    public List<RateResponse> calculateShippingRates(CalculateRateRequest request) {
        try {
            log.info("Calculating shipping rates for request: {}", request);
            return goShipClient.calculateRates(request);
        } catch (Exception e) {
            log.error("Error calculating shipping rates: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to calculate shipping rates: " + e.getMessage());
        }
    }

    @Override
    public ShipmentResponse createShipment(Order order) {
        try {
            log.info("Creating GoShip shipment for order: {}", order.getOrderId());

            // Build request từ Order
            CreateShipmentRequest request = buildShipmentRequest(order);

            // Call GoShip API
            ShipmentResponse response = goShipClient.createShipment(request);

            log.info("Successfully created shipment: {} for order: {}",
                    response.getTrackingCode(), order.getOrderId());

            return response;

        } catch (Exception e) {
            log.error("Error creating shipment for order {}: {}", order.getOrderId(), e.getMessage(), e);
            throw new RuntimeException("Failed to create shipment: " + e.getMessage());
        }
    }

    @Override
    public ShipmentResponse getShipment(String shipmentId) {
        try {
            log.info("Getting shipment info for: {}", shipmentId);
            return goShipClient.getShipment(shipmentId);
        } catch (Exception e) {
            log.error("Error getting shipment {}: {}", shipmentId, e.getMessage(), e);
            throw new RuntimeException("Failed to get shipment: " + e.getMessage());
        }
    }

    @Override
    public void cancelShipment(String shipmentId) {
        try {
            log.info("Cancelling shipment: {}", shipmentId);
            goShipClient.cancelShipment(shipmentId);
            log.info("Successfully cancelled shipment: {}", shipmentId);
        } catch (Exception e) {
            log.error("Error cancelling shipment {}: {}", shipmentId, e.getMessage(), e);
            throw new RuntimeException("Failed to cancel shipment: " + e.getMessage());
        }
    }

    /**
     * Build CreateShipmentRequest từ Order entity
     */
    private CreateShipmentRequest buildShipmentRequest(Order order) {
        // Address From (warehouse)
        CreateShipmentRequest.AddressInfo addressFrom = CreateShipmentRequest.AddressInfo.builder()
                .city(defaultWarehouseCity)
                .district(defaultWarehouseDistrict)
                .ward(defaultWarehouseWard)
                .address(defaultWarehouseAddress)
                .name(defaultWarehouseName)
                .phone(defaultWarehousePhone)
                .build();

        // Address To (customer)
        CreateShipmentRequest.AddressInfo addressTo = CreateShipmentRequest.AddressInfo.builder()
                .city(String.valueOf(order.getShippingAddress().getReceiverProvinceId()))
                .district(String.valueOf(order.getShippingAddress().getReceiverDistrictId()))
                .ward(order.getShippingAddress().getReceiverWardCode())
                .address(order.getShippingAddress().getReceiverAddress())
                .name(order.getShippingAddress().getReceiverName())
                .phone(order.getShippingAddress().getReceiverPhone())
                .build();

        // Parcel info - Tính toán từ order items
        CreateShipmentRequest.ParcelInfo parcel = calculateParcelInfo(order);

        // COD amount
        BigDecimal codAmount = order.getPaymentMethod().name().equals("COD")
                ? order.getTotalPrice()
                : BigDecimal.ZERO;

        // Shipment info
        CreateShipmentRequest.ShipmentInfo shipmentInfo = CreateShipmentRequest.ShipmentInfo.builder()
                .addressFrom(addressFrom)
                .addressTo(addressTo)
                .parcel(parcel)
                .codAmount(codAmount)
                .note(order.getShippingAddress().getNote())
                .build();

        return CreateShipmentRequest.builder()
                .shipment(shipmentInfo)
                .build();
    }

    /**
     * Tính toán thông tin parcel từ order items
     * TODO: Lấy thông tin kích thước/trọng lượng thực tế từ Product service
     */
    private CreateShipmentRequest.ParcelInfo calculateParcelInfo(Order order) {
        // Giá trị mặc định - nên lấy từ product service
        int totalWeight = order.getOrderItems().size() * 500; // 500g/item

        return CreateShipmentRequest.ParcelInfo.builder()
                .weight(totalWeight)
                .length(30) // cm
                .width(20)  // cm
                .height(10) // cm
                .build();
    }
}
