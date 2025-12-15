package com.greenloop.order.dto.simulator;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Response trả về danh sách vận đơn cho Shipper Simulator
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ShipmentSimulatorResponse {

    // Thông tin đơn hàng
    private String orderId;
    private String orderCode;
    private String goshipShipmentId;
    private String goshipTrackingUrl;
    private String carrier;

    // Thông tin người nhận
    private String receiverName;
    private String receiverPhone;
    private String receiverAddress;
    private String receiverWardName;
    private String receiverDistrictName;
    private String receiverCityName;
    private String note;

    // Thông tin kho gửi
    private String warehouseName;
    private String warehousePhone;
    private String warehouseAddress;
    private String warehouseWardName;
    private String warehouseDistrictName;
    private String warehouseCityName;

    // Trạng thái hiện tại
    private Integer currentShippingStatus;
    private String currentShippingStatusText;
    private String orderStatus;
    private String orderStatusDescription;

    // Thông tin kiện hàng
    private String parcelWeight;
    private String parcelLength;
    private String parcelWidth;
    private String parcelHeight;

    // Thông tin thanh toán
    private BigDecimal totalPrice;
    private String paymentMethod;
    private String paymentStatus;

    // Metadata
    private LocalDateTime createdAt;
    private LocalDateTime expectedDeliveryTime;
    private LocalDateTime updatedAt;
}
