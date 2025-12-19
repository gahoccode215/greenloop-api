package com.greenloop.product.dto.request;

import lombok.Builder;
import lombok.Data;
import java.util.List;

@Data
@Builder
public class MarkProductsSoldRequest {
    private String orderId;
    private List<ProductSold> products;

    @Data
    @Builder
    public static class ProductSold {
        private Long productId;
        private Integer ecoPointValue;
    }
}
