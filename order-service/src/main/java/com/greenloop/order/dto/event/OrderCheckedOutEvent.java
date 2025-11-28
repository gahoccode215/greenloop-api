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
public class OrderCheckedOutEvent implements Serializable {

    private String orderId;
    private Long customerId;
    private BigDecimal totalAmount;
    private LocalDateTime checkedOutAt;
    private List<ProductStatusChange> productStatusChanges;
    private Integer totalEcoPoints;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ProductStatusChange implements Serializable {
        private Long productId;
        private String newStatus;
        private Integer ecoPointValue;
    }
}
