package com.greenloop.order.dto.simulator;

import com.fasterxml.jackson.annotation.JsonInclude;
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
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ShipmentSimulatorResponse {

    // Common fields
    private String orderId;
    private String orderCode;

    // Shipment info - dùng chung
    private String goshipShipmentId;
    private String goshipTrackingUrl;
    private String carrier;
    private Integer currentShippingStatus;
    private String currentShippingStatusText;

    // Order specific fields
    private String orderStatus;
    private String orderStatusDescription;
    private BigDecimal totalPrice;
    private String paymentMethod;
    private String paymentStatus;
    private String note;
    private LocalDateTime expectedDeliveryTime;

    // Return specific fields
    private Long returnRequestId;
    private Long customerId;
    private String returnShipmentId;
    private String returnTrackingUrl;
    private String returnCarrier;
    private Integer currentReturnShippingStatus;
    private String currentReturnShippingStatusText;
    private String returnRequestStatus;
    private String returnRequestStatusText;
    private String returnReason;
    private String returnType;
    private BigDecimal originalAmount;
    private BigDecimal refundAmount;

    // Address - sender (warehouse cho order, customer cho return)
    private String senderName;
    private String senderPhone;
    private String senderAddress;
    private String senderWardName;
    private String senderDistrictName;
    private String senderCityName;

    // Address - receiver (customer cho order, warehouse cho return)
    private String receiverName;
    private String receiverPhone;
    private String receiverAddress;
    private String receiverWardName;
    private String receiverDistrictName;
    private String receiverCityName;

    // Warehouse info - giữ lại cho backward compatibility
    private String warehouseName;
    private String warehousePhone;
    private String warehouseAddress;
    private String warehouseWardName;
    private String warehouseDistrictName;
    private String warehouseCityName;

    // Return pickup info - giữ lại cho backward compatibility
    private String pickupName;
    private String pickupPhone;
    private String pickupAddress;
    private String pickupWardName;
    private String pickupDistrictName;
    private String pickupCityName;

    // Parcel info
    private String parcelWeight;
    private String parcelLength;
    private String parcelWidth;
    private String parcelHeight;

    // Time fields
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime requestedAt;
    private LocalDateTime approvedAt;
    private LocalDateTime returnedAt;
    private LocalDateTime completedAt;
}
