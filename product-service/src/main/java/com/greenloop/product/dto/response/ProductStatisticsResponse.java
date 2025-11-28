package com.greenloop.product.dto.response;

import com.greenloop.product.enums.ConditionGrade;
import com.greenloop.product.enums.ProductStatus;
import com.greenloop.product.enums.ProductType;
import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@Builder
public class ProductStatisticsResponse {
    private Long totalProducts;
    private Map<ProductStatus, Long> productsByStatus;
    private Map<ProductType, Long> productsByType;
    private Map<ConditionGrade, Long> productsByCondition;
    private List<TopProduct> topProducts;

    @Data
    @Builder
    public static class TopProduct {
        private Long productId;
        private String name;
        private Long soldCount;
    }
}
