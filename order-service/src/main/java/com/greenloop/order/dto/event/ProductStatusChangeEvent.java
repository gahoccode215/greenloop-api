package com.greenloop.order.dto.event;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProductStatusChangeEvent {

    private String orderId;
    private String orderCode;
    private String eventType;                  // Ví dụ: "IN_TRANSIT", "LOST"
    private List<ProductStatusChange> productChanges;
    private LocalDateTime timestamp;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ProductStatusChange {
        private Long productId;
        private String oldStatus;
        private String newStatus;
    }
}
