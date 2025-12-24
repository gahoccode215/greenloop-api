package com.greenloop.order.dto.simulator;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ShipmentSimulatorResponse {

    private String orderId;
    private String orderCode;
    private String goshipShipmentId;
    private String goshipTrackingUrl;
    private String carrier;

    private String receiverName;
    private String receiverPhone;
    private String receiverAddress;
    private String receiverWardName;
    private String receiverDistrictName;
    private String receiverCityName;
    private String note;

    private String warehouseName;
    private String warehousePhone;
    private String warehouseAddress;
    private String warehouseWardName;
    private String warehouseDistrictName;
    private String warehouseCityName;

    private Integer currentShippingStatus;
    private String currentShippingStatusText;
    private String orderStatus;
    private String orderStatusDescription;

    private String parcelWeight;
    private String parcelLength;
    private String parcelWidth;
    private String parcelHeight;

    private BigDecimal totalPrice;
    private String paymentMethod;
    private String paymentStatus;

    private LocalDateTime createdAt;
    private LocalDateTime expectedDeliveryTime;
    private LocalDateTime updatedAt;
}
