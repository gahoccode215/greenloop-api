package com.greenloop.order.dto.response;

import com.greenloop.order.dto.BankInfoDTO;
import com.greenloop.order.enums.ReturnReason;
import com.greenloop.order.enums.ReturnRequestStatus;
import com.greenloop.order.enums.ReturnType;
import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ReturnRequestResponse {
    private Long returnRequestId;
    private String orderId;
    private String orderCode;
    private Long customerId;

    private List<ReturnProductItem> returnProducts;

    private ReturnReason returnReason;
    private String returnReasonText;
    private String description;
    private List<String> images;
    private ReturnType returnType;
    private String returnTypeText;
    private BankInfoDTO bankInfo;

    private ReturnRequestStatus status;
    private String statusText;

    private String returnShipmentId;
    private String returnTrackingUrl;
    private String returnCarrier;
    private Integer returnShippingStatus;
    private BigDecimal estimatedReturnShippingFee;
    private BigDecimal actualReturnShippingFee;

    private BigDecimal originalAmount;
    private BigDecimal refundAmount;

    private String rejectedReason;
    private LocalDateTime approvedAt;
    private LocalDateTime rejectedAt;

    private String inspectionNote;
    private List<String> inspectionImages;
    private LocalDateTime inspectedAt;

    private LocalDateTime requestedAt;
    private LocalDateTime returnedAt;
    private LocalDateTime completedAt;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class ReturnProductItem {
        private Long productId;
        private String productName;
        private String productImage;
        private BigDecimal price;
        private Integer ecoPoint;
    }
}
