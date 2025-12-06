package com.greenloop.order.dto.event;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrderCancelledEvent implements Serializable {
    private String orderId;
    private String orderCode;
    private LocalDateTime cancelledAt;
    private String reason;
    private List<ProductStatusChange> productStatusChanges;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ProductStatusChange implements Serializable {
        private Long productId;
        private String newStatus;
    }
}
