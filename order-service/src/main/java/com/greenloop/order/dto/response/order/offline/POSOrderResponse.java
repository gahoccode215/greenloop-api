package com.greenloop.order.dto.response.order.offline;

import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class POSOrderResponse {

    private String orderId;
    private String orderCode;
    private Long customerId;
    private String customerName;
    private String customerPhone;
    private Long eventLocationId;
    private String eventLocationName; // Optional, từ Event Service
    private OrderType orderType;
    private OrderStatus orderStatus;
    private BigDecimal totalAmount;
    private List<ProductInOrder> products;
    private PaymentInfo payment;
    private Integer ecoPointsEarned;
    private Long processedByStaffId;
    private String processedByStaffName; // Optional
    private String notes;
    private LocalDateTime createdAt;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ProductInOrder {
        private Long productId;
        private String productName;
        private String productImage;
        private BigDecimal price;
        private Integer ecoPointValue;
        private Integer quantity; // Always 1 for offline
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PaymentInfo {
        private PaymentMethod method;
        private BigDecimal totalAmount;
        private BigDecimal cashAmount;
        private Integer ecoPointsUsed;
        private BigDecimal ecoPointsValueInMoney; // Giá trị điểm quy đổi
    }
}
