package com.greenloop.order.dto.request;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
public class UpdateProductStatusRequest {

    private String orderId;
    private String orderCode;
    private List<ProductStatusUpdate> productUpdates;
    private LocalDateTime updatedAt;

    @Data
    @Builder
    public static class ProductStatusUpdate {
        private Long productId;
        private String oldStatus;
        private String newStatus;
    }
}
