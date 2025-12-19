package com.greenloop.order.dto.request;

import lombok.Builder;
import lombok.Data;
import java.util.List;

@Data
@Builder
public class UnreserveProductsRequest {
    private String orderId;
    private List<ProductUnreserve> products;

    @Data
    @Builder
    public static class ProductUnreserve {
        private Long productId;
    }
}
