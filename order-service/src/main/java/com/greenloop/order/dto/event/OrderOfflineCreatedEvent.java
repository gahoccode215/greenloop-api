package com.greenloop.order.dto.event;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrderOfflineCreatedEvent implements Serializable {

    private String orderId;
    private String orderCode;
    private Long eventId;
    private Long customerId;
    private Boolean isGuestPurchase;
    private BigDecimal totalAmount;
    private LocalDateTime createdAt;
    private List<ProductStatusChange> productStatusChanges;
    private Integer earnedEcoPoints;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ProductStatusChange implements Serializable {
        private Long productId;
        private String newStatus;
    }
}
