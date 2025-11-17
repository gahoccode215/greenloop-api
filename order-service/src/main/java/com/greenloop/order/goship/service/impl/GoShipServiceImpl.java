package com.greenloop.order.goship.service.impl;

import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.ShippingAddress;
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


    @Override
    public List<RateResponse> calculateShippingRates(CalculateRateRequest request) {
        try {

            return goShipClient.calculateRates(request);

        } catch (Exception e) {
            throw new RuntimeException("Không thể tính cước phí vận chuyển: " + e.getMessage());
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



    private CreateShipmentRequest buildShipmentRequest(Order order) {
        ShippingAddress shippingAddr = order.getShippingAddress();

        // Build Address From (warehouse) - Ưu tiên từ Order
        CreateShipmentRequest.AddressInfo addressFrom = buildWarehouseAddress(shippingAddr);

        // Build Address To (customer)
        CreateShipmentRequest.AddressInfo addressTo = CreateShipmentRequest.AddressInfo.builder()
                .city(String.valueOf(shippingAddr.getReceiverCityId()))
                .district(String.valueOf(shippingAddr.getReceiverDistrictId()))
                .ward(shippingAddr.getReceiverWardCode())
                .address(shippingAddr.getReceiverAddress())
                .name(shippingAddr.getReceiverName())
                .phone(shippingAddr.getReceiverPhone())
                .build();

        // Parcel info - Tính toán từ order items
        CreateShipmentRequest.ParcelInfo parcel = calculateParcelInfo(order);

        // COD amount
        BigDecimal codAmount = "COD".equals(order.getPaymentMethod().name())
                ? order.getTotalPrice()
                : BigDecimal.ZERO;

        // Shipment info
        CreateShipmentRequest.ShipmentInfo shipmentInfo = CreateShipmentRequest.ShipmentInfo.builder()
                .addressFrom(addressFrom)
                .addressTo(addressTo)
                .parcel(parcel)
                .codAmount(codAmount)
                .note(shippingAddr.getNote())
                .build();

        return CreateShipmentRequest.builder()
                .shipment(shipmentInfo)
                .build();
    }


    private CreateShipmentRequest.AddressInfo buildWarehouseAddress(ShippingAddress shippingAddr) {

            return CreateShipmentRequest.AddressInfo.builder()
                    .city(String.valueOf(shippingAddr.getWarehouseCityId()))
                    .district(String.valueOf(shippingAddr.getWarehouseDistrictId()))
                    .ward(shippingAddr.getWarehouseWardCode())
                    .address(shippingAddr.getWarehouseAddress())
                    .name(shippingAddr.getWarehouseName())
                    .phone(shippingAddr.getWarehousePhone())
                    .build();
    }



    /**
     * Tính toán thông tin parcel từ order items
     * TODO: Lấy thông tin kích thước/trọng lượng thực tế từ Product service
     */
    private CreateShipmentRequest.ParcelInfo calculateParcelInfo(Order order) {
        // TODO: Call Product Service để lấy weight/dimensions thực tế
        // Tạm thời dùng giá trị mặc định

        int totalWeight = order.getOrderItems().size() * 500; // 500g/item

        return CreateShipmentRequest.ParcelInfo.builder()
                .weight(totalWeight)
                .length(30) // cm
                .width(20)  // cm
                .height(10) // cm
                .build();
    }


}
