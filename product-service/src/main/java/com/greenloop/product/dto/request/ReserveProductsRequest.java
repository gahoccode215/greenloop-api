package com.greenloop.product.dto.request;

import lombok.Builder;
import lombok.Data;
import java.util.List;

@Data
@Builder
public class ReserveProductsRequest {
    private String orderId;
    private Long customerId;
    private List<ProductReserve> products;

    @Data
    @Builder
    public static class ProductReserve {
        private Long productId;
    }
}
