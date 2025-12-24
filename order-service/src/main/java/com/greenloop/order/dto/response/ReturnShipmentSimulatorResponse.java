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
public class ReturnShipmentSimulatorResponse {

    private Long returnRequestId;
    private String orderId;
    private String orderCode;
    private Long customerId;

    // Thông tin vận đơn return
    private String returnShipmentId;
    private String returnTrackingUrl;
    private String returnCarrier;
    private Integer currentReturnShippingStatus;
    private String currentReturnShippingStatusText;

    // Thông tin ReturnRequest
    private String returnRequestStatus;
    private String returnRequestStatusText;
    private String returnReason;
    private String returnType;
    private BigDecimal originalAmount;
    private BigDecimal refundAmount;

    // Địa chỉ pickup (từ customer)
    private String pickupName;
    private String pickupPhone;
    private String pickupAddress;
    private String pickupWardName;
    private String pickupDistrictName;
    private String pickupCityName;

    // Địa chỉ nhận (kho)
    private String warehouseName;
    private String warehousePhone;
    private String warehouseAddress;
    private String warehouseWardName;
    private String warehouseDistrictName;
    private String warehouseCityName;

    // Thời gian
    private LocalDateTime requestedAt;
    private LocalDateTime approvedAt;
    private LocalDateTime returnedAt;
    private LocalDateTime completedAt;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
