package com.greenloop.product.dto.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MarkOfflineProductsSoldRequest {
    private String orderId;
    private Long eventId;
    private List<ProductSold> products;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ProductSold {
        private Long productId;
    }
}
