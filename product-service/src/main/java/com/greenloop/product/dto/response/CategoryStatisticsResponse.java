package com.greenloop.product.dto.response;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class CategoryStatisticsResponse {
    private Long totalCategories;
    private List<CategoryCount> categoryCounts;

    @Data
    @Builder
    public static class CategoryCount {
        private Long categoryId;
        private String name;
        private Long productCount;
    }
}
